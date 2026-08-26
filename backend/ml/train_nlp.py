import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support

logger = logging.getLogger(__name__)

LABEL2ID = {
    "Legitimate": 0,
    "Suspicious": 1,
    "Phishing": 2,
    "BEC/Fraud": 3,
    "Impersonation": 4,
}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}


class NLPTrainer:
    """Trainer wrapper for fine-tuning transformer models on email threat classification."""

    def __init__(
        self,
        model_name: str = "distilroberta-base",
        output_dir: str = "ml/models/nlp_classifier",
        num_labels: int = 5,
    ):
        self.model_name = model_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.num_labels = num_labels
        self.model = None
        self.tokenizer = None
        self.trainer = None

    def initialize_model(self):
        """Lazy-initialize transformer model and tokenizer."""
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=self.num_labels,
            id2label=ID2LABEL,
            label2id=LABEL2ID,
            problem_type="single_label_classification",
        )
        return self.model, self.tokenizer

    def create_hf_dataset(self, df: pd.DataFrame):
        """Convert a Pandas DataFrame into a tokenized HuggingFace Dataset."""
        import datasets
        if self.tokenizer is None:
            self.initialize_model()

        ds = datasets.Dataset.from_pandas(df[["text", "label"]])
        ds = ds.map(
            lambda x: self.tokenizer(
                x["text"],
                truncation=True,
                padding="max_length",
                max_length=512,
            ),
            batched=True,
        )
        ds = ds.map(lambda x: {"labels": LABEL2ID[x["label"]]})
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

    def train(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
    ):
        """Execute transformer fine-tuning pipeline."""
        from transformers import TrainingArguments, Trainer, EarlyStoppingCallback
        if self.model is None or self.tokenizer is None:
            self.initialize_model()

        train_dataset = self.create_hf_dataset(train_df)
        val_dataset = self.create_hf_dataset(val_df)

        training_args = TrainingArguments(
            output_dir=str(self.output_dir),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size * 2,
            learning_rate=learning_rate,
            weight_decay=0.01,
            warmup_ratio=0.1,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1_macro",
            greater_is_better=True,
            logging_steps=20,
            report_to="none",
        )

        self.trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
        )

        logger.info(f"Starting NLP fine-tuning ({self.model_name}) for {epochs} epochs...")
        self.trainer.train()
        self.save()
        return self.trainer

    def evaluate(self, test_df: pd.DataFrame) -> Dict[str, Any]:
        """Evaluate model performance on held-out test set."""
        if self.trainer is None:
            raise RuntimeError("Model must be trained or loaded before evaluation.")

        test_dataset = self.create_hf_dataset(test_df)
        preds = self.trainer.predict(test_dataset)
        pred_labels = np.argmax(preds.predictions, axis=-1)
        true_labels = preds.label_ids

        report = classification_report(
            true_labels,
            pred_labels,
            target_names=list(LABEL2ID.keys()),
            output_dict=True,
            zero_division=0,
        )
        return report

    def save(self):
        """Save fine-tuned weights and tokenizer to output directory."""
        if self.trainer:
            self.trainer.save_model(str(self.output_dir))
        elif self.model:
            self.model.save_pretrained(str(self.output_dir))
        if self.tokenizer:
            self.tokenizer.save_pretrained(str(self.output_dir))
        logger.info(f"Model and tokenizer saved to {self.output_dir}")


if __name__ == "__main__":
    import argparse
    from ml.data.prepare_datasets import DatasetPreparer

    parser = argparse.ArgumentParser(description="Train Transformer NLP Classifier.")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs.")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size per device.")
    parser.add_argument("--model-name", type=str, default="distilroberta-base", help="Base model identifier.")
    parser.add_argument("--output-dir", type=str, default="ml/models/nlp_classifier", help="Output model directory.")
    args = parser.parse_args()

    preparer = DatasetPreparer()
    print("Preparing NLP datasets...")
    train_df, val_df, test_df = preparer.prepare_nlp_dataset()

    trainer = NLPTrainer(model_name=args.model_name, output_dir=args.output_dir)
    print(f"Starting NLP training ({args.model_name}, {args.epochs} epochs)...")
    trainer.train(train_df, val_df, epochs=args.epochs, batch_size=args.batch_size)
    print("Training finished.")

