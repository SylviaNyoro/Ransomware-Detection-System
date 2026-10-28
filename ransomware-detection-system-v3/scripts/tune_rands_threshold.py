"""
Tune the RanDS Random Forest decision threshold.

Uses validation data only.
The test set remains untouched.
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

DATASET = Path("data/processed/rands_features_50000.csv")
MANIFEST = Path("results/rands_grouped/split_manifest.csv")
MODEL_PATH = Path("models/rands_random_forest_grouped.joblib")
OUTPUT = Path("results/rands_grouped")

MIN_RECALL = 0.85


def calculate_metrics(y, predictions):
    tn, fp, fn, tp = confusion_matrix(
        y, predictions, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(
            y, predictions, zero_division=0
        ),
        "recall": recall_score(
            y, predictions, zero_division=0
        ),
        "f1_score": f1_score(
            y, predictions, zero_division=0
        ),
        "false_positive_rate": (
            fp / (fp + tn) if fp + tn else 0
        ),
        "false_negative_rate": (
            fn / (fn + tp) if fn + tp else 0
        ),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_columns = bundle["feature_columns"]

    if df["sha256"].duplicated().any():
        raise ValueError("Duplicate dataset SHA256")

    if manifest["sha256"].duplicated().any():
        raise ValueError("Duplicate manifest SHA256")

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        how="inner",
        validate="one_to_one",
    )

    if len(merged) != len(df):
        raise ValueError("Dataset and manifest do not match")

    validation = merged[
        merged["split"] == "validation"
    ].copy()

    X = validation[feature_columns]
    y = validation["label"].to_numpy()

    ransomware_index = list(
        model.classes_
    ).index(1)

    probabilities = model.predict_proba(X)[
        :, ransomware_index
    ]

    thresholds = np.round(
        np.arange(0.50, 0.951, 0.025),
        3,
    )

    results = []

    for threshold in thresholds:
        predictions = (
            probabilities >= threshold
        ).astype(int)

        result = calculate_metrics(
            y, predictions
        )

        result["threshold"] = float(threshold)
        results.append(result)

    table = pd.DataFrame(results)

    OUTPUT.mkdir(parents=True, exist_ok=True)

    table.to_csv(
        OUTPUT / "threshold_comparison.csv",
        index=False,
    )

    print("\n=== VALIDATION THRESHOLD COMPARISON ===")

    print(
        table[
            [
                "threshold",
                "accuracy",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
                "false_negative_rate",
            ]
        ].round(4).to_string(index=False)
    )

    eligible = table[
        table["recall"] >= MIN_RECALL
    ]

    if eligible.empty:
        print(
            "\nNo threshold meets minimum recall."
        )
        return

    selected = eligible.sort_values(
        [
            "false_positive_rate",
            "f1_score",
        ],
        ascending=[True, False],
    ).iloc[0]

    print("\n=== SELECTED THRESHOLD ===")
    print("Threshold:", selected["threshold"])
    print("Validation accuracy:", round(selected["accuracy"], 4))
    print("Validation recall:", round(selected["recall"], 4))
    print(
        "Validation FPR:",
        round(selected["false_positive_rate"], 4),
    )
    print("Validation F1:", round(selected["f1_score"], 4))

    selection = {
        "threshold": float(selected["threshold"]),
        "minimum_recall": MIN_RECALL,
        "selection_dataset": "validation",
        "validation_metrics": {
            key: (
                int(selected[key])
                if key in ("tn", "fp", "fn", "tp")
                else float(selected[key])
            )
            for key in [
                "accuracy",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
                "false_negative_rate",
                "tn",
                "fp",
                "fn",
                "tp",
            ]
        },
    }

    with open(
        OUTPUT / "selected_threshold.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(selection, f, indent=2)

    print(
        "\nSaved:",
        OUTPUT / "selected_threshold.json",
    )


if __name__ == "__main__":
    main()
