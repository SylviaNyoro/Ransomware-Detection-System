import pandas as pd

from src.model.augmentation import FEATURE_COLUMNS, augment_training_set


def _toy_imbalanced_split():
    X = pd.DataFrame({
        "modification_frequency": [0, 1, 2, 8, 7, 9, 6, 10, 3, 4, 5, 11],
        "extension_change_rate": [0, 0, 1, 3, 2, 3, 2, 3, 1, 1, 2, 3],
        "file_access_breadth": [0, 1, 1, 8, 6, 9, 7, 10, 2, 3, 4, 12],
    })
    y = pd.Series([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1], name="label")  # 3 minority / 9 majority
    return X, y


def test_augment_none_returns_unchanged():
    X, y = _toy_imbalanced_split()
    X_aug, y_aug = augment_training_set(X, y, method="none")
    assert X_aug.equals(X)
    assert y_aug.equals(y)


def test_smote_balances_classes():
    X, y = _toy_imbalanced_split()
    X_aug, y_aug = augment_training_set(X, y, method="smote", k_neighbors=2, random_state=1)
    counts = y_aug.value_counts()
    assert counts[0] == counts[1]  # balanced after augmentation
    assert len(X_aug) > len(X)  # synthetic rows were added
    assert len(X_aug) == len(y_aug)


def test_adasyn_runs_and_increases_minority():
    X, y = _toy_imbalanced_split()
    X_aug, y_aug = augment_training_set(X, y, method="adasyn", k_neighbors=2, random_state=1)
    assert (y_aug == 0).sum() > (y == 0).sum()


def test_augmented_features_are_nonnegative_integers():
    X, y = _toy_imbalanced_split()
    X_aug, y_aug = augment_training_set(X, y, method="smote", k_neighbors=2, random_state=1)
    for col in FEATURE_COLUMNS:
        assert (X_aug[col] >= 0).all()
        assert pd.api.types.is_integer_dtype(X_aug[col])


def test_too_few_minority_samples_falls_back_gracefully():
    X = pd.DataFrame({
        "modification_frequency": [0, 5, 6],
        "extension_change_rate": [0, 2, 3],
        "file_access_breadth": [0, 4, 5],
    })
    y = pd.Series([0, 1, 1], name="label")  # only 1 minority sample -- can't SMOTE at all
    X_aug, y_aug = augment_training_set(X, y, method="smote", k_neighbors=3)
    assert X_aug.equals(X)  # falls back to unaugmented rather than erroring
    assert y_aug.equals(y)
