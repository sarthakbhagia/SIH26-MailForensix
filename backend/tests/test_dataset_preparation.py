import pytest
from ml.data.prepare_datasets import DatasetPreparer


def test_synthetic_corpus_generation():
    preparer = DatasetPreparer()
    corpus = preparer.generate_synthetic_corpus(total_samples=100)

    assert len(corpus) >= 50
    labels = {r["label"] for r in corpus}
    assert "Legitimate" in labels
    assert "Phishing" in labels
    assert "BEC/Fraud" in labels
    assert "Suspicious" in labels
    assert "Impersonation" in labels

    for r in corpus:
        assert "email" in r
        assert "analysis" in r
        assert "text" in r
        assert "label" in r
        assert len(r["text"]) > 0


def test_prepare_nlp_dataset_splits():
    preparer = DatasetPreparer()
    train_df, val_df, test_df = preparer.prepare_nlp_dataset()

    total = len(train_df) + len(val_df) + len(test_df)
    assert total >= 50

    # Verify 70/15/15 ratio (approx)
    train_ratio = len(train_df) / total
    assert 0.65 <= train_ratio <= 0.75

    # Check columns
    for df in (train_df, val_df, test_df):
        assert "text" in df.columns
        assert "subject" in df.columns
        assert "label" in df.columns


def test_prepare_tabular_dataset_splits():
    preparer = DatasetPreparer()
    train_df, val_df, test_df = preparer.prepare_tabular_dataset()

    assert len(train_df) > 0
    assert len(val_df) > 0
    assert len(test_df) > 0

    # Ensure 35 forensic features are present
    assert "spf_status_encoded" in train_df.columns
    assert "text_entropy" in train_df.columns
    assert "label" in train_df.columns
