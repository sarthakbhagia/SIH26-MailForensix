"""Transformer NLP Threat Classifier Training Pipeline for MailForensix.

Fine-tunes DistilRoBERTa on email [SUBJECT] and [BODY] text with class-weighted loss,
authoritative 5-class label mapping, early stopping on validation macro-F1,
and probability prediction capabilities.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import yaml
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support
from sklearn.utils.class_weight import compute_class_weight

from ml.src.preprocessing.nlp_dataset import NLPDatasetLoader

logger = logging.getLogger(__name__)

# Authoritative 5-Class Taxonomy from labels.yaml
LABEL2ID: Dict[str, int] = {
    "LEGITIMATE": 0,
    "SUSPICIOUS": 1,
    "PHISHING": 2,
    "BEC_FRAUD": 3,
    "IMPERSONATION": 4,
}
ID2LABEL: Dict[int, str] = {v: k for k, v in LABEL2ID.items()}


class ClassWeightedTrainer(object):
    """Custom HuggingFace Trainer applying class-weighted cross-entropy loss."""
    pass


def get_weighted_trainer_class():
    from transformers import Trainer

    class _WeightedTrainer(Trainer):
        def __init__(self, *args, class_weights: Optional[List[float]] = None, **kwargs):
            super().__init__(*args, **kwargs)
            self.class_weights = class_weights

        def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
            labels = inputs.get("labels")
            outputs = model(**inputs)
            logits = outputs.get("logits")
            if self.class_weights is not None:
                weight_tensor = torch.tensor(self.class_weights, dtype=torch.float, device=model.device)
                loss_fct = nn.CrossEntropyLoss(weight=weight_tensor)
            else:
                loss_fct = nn.CrossEntropyLoss()
            loss = loss_fct(logits.view(-1, model.config.num_labels), labels.view(-1))
            return (loss, outputs) if return_outputs else loss

    return _WeightedTrainer


class NLPTrainer:
    """Trainer wrapper for fine-tuning DistilRoBERTa on email threat classification."""

    def __init__(
        self,
        model_name: str = "distilroberta-base",
        output_dir: str = "ml/models/nlp_classifier",
        num_labels: int = 5,
        random_seed: int = 42,
    ):
        self.model_name = model_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.num_labels = num_labels
        self.random_seed = random_seed
        self.model = None
        self.tokenizer = None
        self.trainer = None
        self.class_weights = None

    def initialize_model(self):
        """Lazy-initialize transformer model and tokenizer."""
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, set_seed
        set_seed(self.random_seed)
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=self.num_labels,
            id2label=ID2LABEL,
            label2id=LABEL2ID,
            problem_type="single_label_classification",
        )
        return self.model, self.tokenizer

    def create_hf_dataset(self, df: pd.DataFrame, max_length: Optional[int] = None):
        """Convert a Pandas DataFrame into a tokenized HuggingFace Dataset."""
        import datasets
        if self.tokenizer is None:
            self.initialize_model()

        max_len = max_length or (512 if torch.cuda.is_available() else 128)
        ds = datasets.Dataset.from_pandas(df[["text", "label"]])
        ds = ds.map(
            lambda x: self.tokenizer(
                x["text"],
                truncation=True,
                padding="max_length",
                max_length=max_len,
            ),
            batched=True,
        )
        ds = ds.map(lambda x: {"labels": int(x["label"]) if isinstance(x["label"], (int, np.integer)) else LABEL2ID.get(str(x["label"]), 0)})
        ds.set_format("torch", columns=["input_ids", "attention_mask", "labels"])
        return ds

    @staticmethod
    def compute_metrics(eval_pred) -> Dict[str, float]:
        """Compute accuracy, precision, recall, and macro F1 score."""
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predictions, average="macro", zero_division=0
        )
        accuracy = (predictions == labels).mean()
        return {
            "accuracy": float(accuracy),
            "f1_macro": float(f1),
            "precision_macro": float(precision),
            "recall_macro": float(recall),
        }

    def compute_train_class_weights(self, train_df: pd.DataFrame) -> List[float]:
        """Compute balanced class weights exclusively from Train split."""
        labels = train_df["label"].values.astype(int)
        unique_classes = np.arange(self.num_labels)
        weights = compute_class_weight("balanced", classes=unique_classes, y=labels)
        # Cap max weight to prevent extreme gradient swings on small classes
        capped_weights = np.clip(weights, 0.2, 5.0).tolist()
        self.class_weights = capped_weights
        logger.info(f"Computed Train class weights: {dict(zip(ID2LABEL.values(), [round(w, 3) for w in capped_weights]))}")
        return capped_weights

    def train(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        epochs: int = 2,
        batch_size: int = 16,
        learning_rate: float = 3e-5,
    ):
        """Execute transformer fine-tuning pipeline with class-weighted loss."""
        from transformers import TrainingArguments, EarlyStoppingCallback
        if self.model is None or self.tokenizer is None:
            self.initialize_model()

        use_cuda = torch.cuda.is_available()

        # Optimize for CPU execution if CUDA unavailable
        if not use_cuda:
            # Freeze bottom 4 layers of encoder to accelerate CPU training
            if hasattr(self.model, "roberta"):
                for param in self.model.roberta.embeddings.parameters():
                    param.requires_grad = False
                for layer in self.model.roberta.encoder.layer[:4]:
                    for param in layer.parameters():
                        param.requires_grad = False
            # Stratified sampling for fast CPU training while maintaining exact class balance
            from sklearn.model_selection import train_test_split
            if len(train_df) > 2000:
                train_data, _ = train_test_split(
                    train_df,
                    train_size=min(2000, len(train_df)),
                    stratify=train_df["label"],
                    random_state=self.random_seed,
                )
                train_data = train_data.reset_index(drop=True)
            else:
                train_data = train_df
            actual_batch_size = max(batch_size, 32)
            actual_epochs = 1
        else:
            train_data = train_df
            actual_batch_size = batch_size
            actual_epochs = epochs

        # Compute class weights strictly on Train split
        class_weights = self.compute_train_class_weights(train_data)

        train_dataset = self.create_hf_dataset(train_data)
        val_dataset = self.create_hf_dataset(val_df)

        training_args = TrainingArguments(
            output_dir=str(self.output_dir),
            num_train_epochs=actual_epochs,
            per_device_train_batch_size=actual_batch_size,
            per_device_eval_batch_size=actual_batch_size * 2,
            learning_rate=learning_rate,
            weight_decay=0.01,
            warmup_steps=30,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1_macro",
            greater_is_better=True,
            logging_steps=20,
            report_to="none",
            seed=self.random_seed,
            fp16=use_cuda,
        )

        TrainerClass = get_weighted_trainer_class()
        self.trainer = TrainerClass(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
            class_weights=class_weights,
        )

        logger.info(f"Starting NLP fine-tuning ({self.model_name}) on device {'CUDA' if use_cuda else 'CPU'} for {epochs} epochs...")
        self.trainer.train()
        self.save()
        return self.trainer

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Generate softmax probability matrix of shape (n_samples, 5)."""
        if self.trainer is None:
            self.load()
            from transformers import TrainingArguments
            TrainerClass = get_weighted_trainer_class()
            args = TrainingArguments(output_dir=str(self.output_dir), per_device_eval_batch_size=32, report_to="none")
            self.trainer = TrainerClass(model=self.model, args=args, compute_metrics=self.compute_metrics)

        ds = self.create_hf_dataset(df)
        preds = self.trainer.predict(ds)
        logits = preds.predictions
        # Apply softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
        return probs

    def evaluate(self, test_df: pd.DataFrame) -> Dict[str, Any]:
        """Evaluate model performance on held-out dataset."""
        probs = self.predict_proba(test_df)
        pred_labels = np.argmax(probs, axis=-1)
        true_labels = test_df["label"].values.astype(int)

        target_names = [ID2LABEL[i] for i in range(self.num_labels)]
        report = classification_report(
            true_labels,
            pred_labels,
            target_names=target_names,
            output_dict=True,
            zero_division=0,
        )
        return report

    def save(self):
        """Save fine-tuned weights, tokenizer, and labels to output directory."""
        if self.trainer:
            self.trainer.save_model(str(self.output_dir))
        elif self.model:
            self.model.save_pretrained(str(self.output_dir))
        if self.tokenizer:
            self.tokenizer.save_pretrained(str(self.output_dir))

        # Save authoritative labels and metadata
        with open(self.output_dir / "label_mapping.json", "w", encoding="utf-8") as f:
            json.dump({
                "label2id": LABEL2ID,
                "id2label": ID2LABEL,
                "class_weights": self.class_weights,
            }, f, indent=2)
        logger.info(f"Model, tokenizer, and label mapping saved to {self.output_dir}")

    def load(self):
        """Load trained weights from output directory."""
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.output_dir))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.output_dir))
        self.model.eval()
        return self.model, self.tokenizer


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train DistilRoBERTa NLP Classifier.")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs.")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size per device.")
    parser.add_argument("--model-name", type=str, default="distilroberta-base", help="Base model identifier.")
    parser.add_argument("--output-dir", type=str, default="ml/models/nlp_classifier", help="Output model directory.")
    args = parser.parse_args()

    loader = NLPDatasetLoader()
    print("Loading authoritative NLP splits...")
    train_df, val_df, test_df = loader.load_datasets()

    trainer = NLPTrainer(model_name=args.model_name, output_dir=args.output_dir)
    print(f"Starting NLP training ({args.model_name}, {args.epochs} epochs)...")
    trainer.train(train_df, val_df, epochs=args.epochs, batch_size=args.batch_size)
    print("Evaluating on validation split:")
    val_report = trainer.evaluate(val_df)
    print(json.dumps(val_report, indent=2))
