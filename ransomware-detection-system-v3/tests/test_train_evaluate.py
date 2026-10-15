import pandas as pd
import pytest

from src.model.evaluate import evaluate
from src.model.train import FEATURE_COLUMNS, load_and_preprocess, load_config, train

CFG = load_config()


def test_load_and_preprocess_drops_exact_duplicates():
    df = load_and_preprocess()
    assert len(df) > 0
    assert df.duplicated(subset=FEATURE_COLUMNS + ["label"]).sum() == 0
    assert set(df["label"].unique()) == {0, 1}


def test_train_raises_on_too_small_or_single_class_dataset():
    tiny_df = pd.DataFrame({
        "modification_frequency": [1, 2, 3],
        "extension_change_rate": [1, 1, 1],
        "file_access_breadth": [1, 2, 1],
        "label": [1, 1, 1],  # only one class present
    })
    with pytest.raises(ValueError):
        train(CFG, df=tiny_df)


def test_train_produces_model_and_test_split():
    model, scaler, X_test, y_test = train(CFG)
    assert model is not None
    assert scaler is not None
    assert len(X_test) == len(y_test)
    assert len(X_test) > 0
    # both classes should be present somewhere across train+test given stratify
    assert hasattr(model, "feature_importances_")
    assert len(model.feature_importances_) == len(FEATURE_COLUMNS)


def test_evaluate_returns_all_expected_metrics():
    model, scaler, X_test, y_test = train(CFG)
    metrics = evaluate(model, X_test, y_test)
    expected_keys = {
        "accuracy", "precision", "recall", "f1_score",
        "false_positive_rate", "false_negative_rate",
        "confusion_matrix", "test_set_size",
    }
    assert expected_keys.issubset(metrics.keys())
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["test_set_size"] == len(y_test)


def test_augmentation_never_changes_test_set_size():
    """Core integrity guarantee: augmentation only touches the training
    split. The test split size must be identical whether augmentation
    is enabled or disabled, since it's always drawn from real data only."""
    df = load_and_preprocess()

    cfg_augmented = {**CFG, "augmentation": {**CFG["augmentation"], "enabled": True}}
    cfg_unaugmented = {**CFG, "augmentation": {**CFG["augmentation"], "enabled": False}}

    _, _, X_test_aug, y_test_aug = train(cfg_augmented, df=df)
    _, _, X_test_plain, y_test_plain = train(cfg_unaugmented, df=df)

    assert len(y_test_aug) == len(y_test_plain)
    # Same random_state/stratify -> same actual test rows, not just same count.
    assert (y_test_aug.values == y_test_plain.values).all()
