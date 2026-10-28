"""
Train the seven-feature RanDS filesystem Random Forest.

Uses existing grouped split.
Selects threshold on validation data only.
Does not evaluate the held-out test set.
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.feature_engineering.rands_filesystem_features import (
    FEATURE_COLUMNS,
)


DATASET = Path(
    "data/processed/rands_filesystem_features_50000.csv"
)

MANIFEST = Path(
    "results/rands_grouped/split_manifest.csv"
)

OUTPUT = Path("results/rands_filesystem")
MODEL_PATH = Path(
    "models/rands_random_forest_filesystem.joblib"
)

MIN_RECALL = 0.85


def evaluate(y_true, predictions):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    return {
        "accuracy": float(
            accuracy_score(y_true, predictions)
        ),
        "precision": float(
            precision_score(
                y_true, predictions, zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_true, predictions, zero_division=0
            )
        ),
        "f1_score": float(
            f1_score(
                y_true, predictions, zero_division=0
            )
        ),
        "fpr": float(fp / (fp + tn)),
        "fnr": float(fn / (fn + tp)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    if df["sha256"].duplicated().any():
        raise ValueError("Duplicate dataset SHA256")

    if manifest["sha256"].duplicated().any():
        raise ValueError("Duplicate manifest SHA256")

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        validate="one_to_one",
    )

    if len(merged) != len(df):
        raise ValueError("Dataset/manifest mismatch")

    train = merged[merged["split"] == "train"]
    validation = merged[
        merged["split"] == "validation"
    ]

    # Check that the seven-feature vectors
    # do not overlap between train and validation.
    train_vectors = set(
        map(
            tuple,
            train[FEATURE_COLUMNS].to_numpy(),
        )
    )

    val_vectors = set(
        map(
            tuple,
            validation[FEATURE_COLUMNS].to_numpy(),
        )
    )

    overlap = len(train_vectors & val_vectors)

    print("=== GROUP LEAKAGE CHECK ===")
    print("Train/validation overlap:", overlap)

    if overlap:
        raise ValueError(
            "Feature overlap detected"
        )

    X_train = train[FEATURE_COLUMNS]
    y_train = train["label"]

    X_val = validation[FEATURE_COLUMNS]
    y_val = validation["label"]

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining filesystem Random Forest...")
    model.fit(X_train, y_train)

    probabilities = model.predict_proba(
        X_val
    )[:, list(model.classes_).index(1)]

    rows = []

    for threshold in np.round(
        np.arange(0.50, 0.801, 0.025),
        3,
    ):
        predictions = (
            probabilities >= threshold
        ).astype(int)

        result = evaluate(
            y_val, predictions
        )

        rows.append({
            "threshold": float(threshold),
            **result,
        })

    table = pd.DataFrame(rows)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(
        parents=True, exist_ok=True
    )

    table.to_csv(
        OUTPUT / "validation_thresholds.csv",
        index=False,
    )

    print("\n=== VALIDATION THRESHOLDS ===")
    print(
        table[
            [
                "threshold",
                "accuracy",
                "precision",
                "recall",
                "f1_score",
                "fpr",
                "fnr",
            ]
        ].round(4).to_string(index=False)
    )

    eligible = table[
        table["recall"] >= MIN_RECALL
    ]

    if eligible.empty:
        selected = table.sort_values(
            ["recall", "fpr"],
            ascending=[False, True],
        ).iloc[0]

        print(
            "\nWARNING: No threshold achieved "
            "85% ransomware recall."
        )
    else:
        selected = eligible.sort_values(
            ["fpr", "f1_score"],
            ascending=[True, False],
        ).iloc[0]

    print("\n=== SELECTED VALIDATION RESULT ===")

    for key in [
        "threshold",
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "fpr",
        "fnr",
    ]:
        print(f"{key}: {selected[key]:.4f}")

    print("\n=== TARGET CHECK ===")
    print(
        "Recall >= 85%:",
        selected["recall"] >= 0.85,
    )
    print(
        "FPR < 10%:",
        selected["fpr"] < 0.10,
    )

    bundle = {
        "model": model,
        "feature_columns": list(FEATURE_COLUMNS),
        "threshold": float(selected["threshold"]),
        "dataset": "RanDS",
        "split_method": "grouped",
        "selection_dataset": "validation",
        "random_state": 42,
    }

    joblib.dump(bundle, MODEL_PATH)

    with open(
        OUTPUT / "selected_validation_result.json",
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            {
                "threshold": float(
                    selected["threshold"]
                ),
                "validation_metrics": {
                    key: float(selected[key])
                    for key in [
                        "accuracy",
                        "precision",
                        "recall",
                        "f1_score",
                        "fpr",
                        "fnr",
                    ]
                },
            },
            handle,
            indent=2,
        )

    print("\n=== SAVED ===")
    print("Model:", MODEL_PATH)
    print(
        "Threshold results:",
        OUTPUT / "validation_thresholds.csv",
    )


if __name__ == "__main__":
    main()
