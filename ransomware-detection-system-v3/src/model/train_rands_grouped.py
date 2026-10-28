"""
Leakage-resistant RanDS Random Forest evaluation.

Target:
    70% training
    15% validation
    15% testing

Identical feature vectors remain in the same split.
The class distribution is approximately 70% ransomware
and 30% benign.

No synthetic data is generated.
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

from src.feature_engineering.rands_features import FEATURE_COLUMNS


DATASET = Path("data/processed/rands_features_50000.csv")
MODEL_PATH = Path("models/rands_random_forest_grouped.joblib")
RESULTS_DIR = Path("results/rands_grouped")
SEED = 42


def evaluate(model, X, y):
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    tn, fp, fn, tp = confusion_matrix(
        y, predictions, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions)),
        "recall": float(recall_score(y, predictions)),
        "f1_score": float(f1_score(y, predictions)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "false_positive_rate": float(
            fp / (fp + tn) if fp + tn else 0
        ),
        "false_negative_rate": float(
            fn / (fn + tp) if fn + tp else 0
        ),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def print_distribution(name, y):
    total = len(y)
    counts = y.value_counts().sort_index()

    print(f"\n=== {name.upper()} ===")
    print("Samples:", total)

    for label in [0, 1]:
        count = int(counts.get(label, 0))
        percentage = 100 * count / total

        print(
            f"Class {label}: {count} ({percentage:.2f}%)"
        )


def main():
    df = pd.read_csv(DATASET)

    if df["sha256"].duplicated().any():
        raise ValueError("Duplicate SHA256 detected")

    if df[FEATURE_COLUMNS + ["label"]].isna().any().any():
        raise ValueError("Missing feature or label values")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # Same group ID for identical feature vectors.
    groups = pd.util.hash_pandas_object(
        X, index=False
    ).to_numpy()

    # Initial grouped 5-fold partition.
    # Choose a test fold closest to 15% of all rows.
    splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=SEED,
    )

    candidates = list(
        splitter.split(X, y, groups)
    )

    target_test = 0.15 * len(df)

    dev_idx, test_idx = min(
        candidates,
        key=lambda pair: abs(
            len(pair[1]) - target_test
        ),
    )

    # Split development data into train and validation.
    X_dev = X.iloc[dev_idx]
    y_dev = y.iloc[dev_idx]
    groups_dev = groups[dev_idx]

    second_splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=SEED + 1,
    )

    second_candidates = list(
        second_splitter.split(
            X_dev, y_dev, groups_dev
        )
    )

    target_val = 0.15 * len(df)

    train_local, val_local = min(
        second_candidates,
        key=lambda pair: abs(
            len(pair[1]) - target_val
        ),
    )

    train_idx = dev_idx[train_local]
    val_idx = dev_idx[val_local]

    X_train = X.iloc[train_idx]
    y_train = y.iloc[train_idx]

    X_val = X.iloc[val_idx]
    y_val = y.iloc[val_idx]

    X_test = X.iloc[test_idx]
    y_test = y.iloc[test_idx]

    print("\n=== SPLIT SIZES ===")

    for name, indices in [
        ("Training", train_idx),
        ("Validation", val_idx),
        ("Testing", test_idx),
    ]:
        print(
            f"{name}: {len(indices)} "
            f"({100 * len(indices) / len(df):.2f}%)"
        )

    print_distribution("Training", y_train)
    print_distribution("Validation", y_val)
    print_distribution("Testing", y_test)

    # Confirm groups do not cross splits.
    train_groups = set(groups[train_idx])
    val_groups = set(groups[val_idx])
    test_groups = set(groups[test_idx])

    assert not (train_groups & val_groups)
    assert not (train_groups & test_groups)
    assert not (val_groups & test_groups)

    print("\n=== GROUP LEAKAGE CHECK ===")
    print("Train/validation overlap: 0")
    print("Train/test overlap: 0")
    print("Validation/test overlap: 0")
    print("Status: PASSED")

    model = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1,
    )

    print("\nTraining grouped Random Forest...")
    model.fit(X_train, y_train)

    results = {}

    for name, X_split, y_split in [
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ]:
        results[name] = evaluate(
            model, X_split, y_split
        )

        predictions = model.predict(X_split)

        print(f"\n=== {name.upper()} RESULTS ===")
        print(
            classification_report(
                y_split,
                predictions,
                labels=[0, 1],
                target_names=[
                    "Benign",
                    "Ransomware",
                ],
                zero_division=0,
            )
        )

        print(
            "False positive rate:",
            round(
                results[name]["false_positive_rate"],
                4,
            ),
        )
        print(
            "False negative rate:",
            round(
                results[name]["false_negative_rate"],
                4,
            ),
        )

        print(
            "Confusion matrix:",
            results[name]["confusion_matrix"],
        )

    RESULTS_DIR.mkdir(
        parents=True, exist_ok=True
    )

    MODEL_PATH.parent.mkdir(
        parents=True, exist_ok=True
    )

    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "dataset": "RanDS",
            "split_method": "StratifiedGroupKFold",
            "random_state": SEED,
        },
        MODEL_PATH,
    )

    with open(
        RESULTS_DIR / "metrics.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(results, f, indent=2)

    split_records = df[["sha256", "label"]].copy()
    split_records["split"] = ""

    split_records.loc[train_idx, "split"] = "train"
    split_records.loc[val_idx, "split"] = "validation"
    split_records.loc[test_idx, "split"] = "test"

    split_records.to_csv(
        RESULTS_DIR / "split_manifest.csv",
        index=False,
    )

    print("\n=== SAVED ===")
    print("Model:", MODEL_PATH)
    print("Metrics:", RESULTS_DIR / "metrics.json")
    print(
        "Split manifest:",
        RESULTS_DIR / "split_manifest.csv",
    )


if __name__ == "__main__":
    main()
