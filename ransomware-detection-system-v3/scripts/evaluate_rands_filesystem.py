"""
Evaluate the selected RanDS filesystem model.

Uses the held-out test split.
Does not retrain or tune the model.
"""

from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

DATASET = Path(
    "data/processed/rands_filesystem_features_50000.csv"
)

MANIFEST = Path(
    "results/rands_grouped/split_manifest.csv"
)

MODEL_PATH = Path(
    "models/rands_random_forest_filesystem.joblib"
)

OUTPUT = Path(
    "results/rands_filesystem/test_metrics.json"
)


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    bundle = joblib.load(MODEL_PATH)

    model = bundle["model"]
    features = bundle["feature_columns"]
    threshold = float(bundle["threshold"])

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        how="inner",
        validate="one_to_one",
    )

    if len(merged) != len(df):
        raise ValueError(
            "Dataset and manifest mismatch"
        )

    test = merged[
        merged["split"] == "test"
    ].copy()

    if len(test) != 9999:
        raise ValueError(
            "Unexpected test split size"
        )

    X_test = test[features]
    y_test = test["label"]

    ransomware_index = list(
        model.classes_
    ).index(1)

    probabilities = model.predict_proba(
        X_test
    )[:, ransomware_index]

    predictions = (
        probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    ).ravel()

    metrics = {
        "threshold": threshold,
        "test_samples": int(len(test)),
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision": float(
            precision_score(y_test, predictions)
        ),
        "recall": float(
            recall_score(y_test, predictions)
        ),
        "f1_score": float(
            f1_score(y_test, predictions)
        ),
        "roc_auc": float(
            roc_auc_score(y_test, probabilities)
        ),
        "false_positive_rate": float(
            fp / (fp + tn)
        ),
        "false_negative_rate": float(
            fn / (fn + tp)
        ),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }

    print("\n=== FINAL TEST RESULTS ===")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Benign",
                "Ransomware",
            ],
        )
    )

    print(
        "False positive rate:",
        round(
            metrics["false_positive_rate"],
            4,
        ),
    )

    print(
        "False negative rate:",
        round(
            metrics["false_negative_rate"],
            4,
        ),
    )

    print(
        "ROC-AUC:",
        round(metrics["roc_auc"], 4),
    )

    print(
        "Confusion matrix:",
        metrics["confusion_matrix"],
    )

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            metrics,
            handle,
            indent=2,
        )

    print("\nSaved:", OUTPUT)


if __name__ == "__main__":
    main()
