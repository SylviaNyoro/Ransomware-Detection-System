"""
Train a RanDS-only Random Forest classifier.

Uses a 70/15/15 stratified train/validation/test split.
The test set is reserved for final evaluation.
"""

from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

from src.feature_engineering.rands_features import (
    FEATURE_COLUMNS,
)

DATASET = Path("data/processed/rands_features_50000.csv")
MODEL_PATH = Path("models/rands_random_forest.joblib")
RESULTS_DIR = Path("results/rands_baseline")

RANDOM_STATE = 42


def metrics(y_true, y_pred, probabilities):
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(
            y_true, y_pred, zero_division=0
        ),
        "recall": recall_score(
            y_true, y_pred, zero_division=0
        ),
        "f1_score": f1_score(
            y_true, y_pred, zero_division=0
        ),
        "false_positive_rate": (
            fp / (fp + tn) if fp + tn else 0
        ),
        "false_negative_rate": (
            fn / (fn + tp) if fn + tp else 0
        ),
        "roc_auc": roc_auc_score(
            y_true, probabilities
        ),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def main():
    df = pd.read_csv(DATASET)

    required = FEATURE_COLUMNS + ["label", "sha256"]
    missing = set(required) - set(df.columns)

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    if df["sha256"].duplicated().any():
        raise ValueError("Duplicate SHA256 detected")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # Reserve 15% for final testing.
    X_dev, X_test, y_dev, y_test = train_test_split(
        X,
        y,
        test_size=0.15,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    # 70% train / 15% validation / 15% test.
    X_train, X_val, y_train, y_val = train_test_split(
        X_dev,
        y_dev,
        test_size=0.15 / 0.85,
        stratify=y_dev,
        random_state=RANDOM_STATE,
    )

    print("=== DATA SPLITS ===")
    print("Training:", len(X_train))
    print("Validation:", len(X_val))
    print("Testing:", len(X_test))

    # Audit identical feature vectors across splits.
    def signatures(frame):
        return set(
            map(tuple, frame.to_numpy().tolist())
        )

    train_signatures = signatures(X_train)
    val_signatures = signatures(X_val)
    test_signatures = signatures(X_test)

    print("\n=== FEATURE VECTOR OVERLAP ===")
    print(
        "Train/validation:",
        len(train_signatures & val_signatures),
    )
    print(
        "Train/test:",
        len(train_signatures & test_signatures),
    )
    print(
        "Validation/test:",
        len(val_signatures & test_signatures),
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("\nTraining Random Forest...")
    model.fit(X_train, y_train)

    results = {}

    for name, X_split, y_split in [
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ]:
        predictions = model.predict(X_split)
        probabilities = model.predict_proba(
            X_split
        )[:, 1]

        results[name] = metrics(
            y_split,
            predictions,
            probabilities,
        )

        print(f"\n=== {name.upper()} RESULTS ===")
        print(
            classification_report(
                y_split,
                predictions,
                target_names=["Benign", "Ransomware"],
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
            "random_state": RANDOM_STATE,
        },
        MODEL_PATH,
    )

    with open(
        RESULTS_DIR / "metrics.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(results, f, indent=2)

    importances = pd.DataFrame({
        "feature": FEATURE_COLUMNS,
        "importance": model.feature_importances_,
    }).sort_values(
        "importance", ascending=False
    )

    importances.to_csv(
        RESULTS_DIR / "feature_importance.csv",
        index=False,
    )

    print("\n=== FEATURE IMPORTANCE ===")
    print(importances.to_string(index=False))

    print("\nModel saved:", MODEL_PATH)
    print(
        "Results saved:",
        RESULTS_DIR / "metrics.json",
    )


if __name__ == "__main__":
    main()
