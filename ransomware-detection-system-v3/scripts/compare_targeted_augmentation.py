"""Compare the original and augmented filesystem Random Forest models."""

from pathlib import Path

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

DATASET = Path("data/processed/rands_filesystem_features_50000.csv")
MANIFEST = Path("results/rands_grouped/split_manifest.csv")
SYNTHETIC = Path("data/processed/targeted_benign_synthetic_200.csv")

BASELINE_MODEL = Path("models/rands_random_forest_filesystem.joblib")
EXPERIMENTAL_MODEL = Path("models/rands_random_forest_filesystem_augmented_experiment.joblib")

OUTPUT = Path("results/rands_filesystem/augmentation_experiment")

MIN_RECALL = 0.85


def evaluate(y_true, probabilities, threshold):
    predictions = (probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "threshold": float(threshold),
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(
            y_true, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_true, predictions, zero_division=0
        ),
        "f1": f1_score(
            y_true, predictions, zero_division=0
        ),
        "fpr": fp / (fp + tn),
        "fnr": fn / (fn + tp),
        "fp": int(fp),
        "fn": int(fn),
    }


def select_threshold(y_true, probabilities):
    rows = []

    for threshold in np.round(
        np.arange(0.50, 0.951, 0.025), 3
    ):
        rows.append(
            evaluate(y_true, probabilities, threshold)
        )

    table = pd.DataFrame(rows)

    eligible = table[table["recall"] >= MIN_RECALL]

    if eligible.empty:
        return None, table

    selected = eligible.sort_values(
        ["fpr", "f1"],
        ascending=[True, False],
    ).iloc[0]

    return selected, table


def main():
    baseline = joblib.load(BASELINE_MODEL)
    features = baseline["feature_columns"]

    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)
    synthetic = pd.read_csv(SYNTHETIC)

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        validate="one_to_one",
    )

    train = merged[merged["split"] == "train"]
    validation = merged[merged["split"] == "validation"]

    X_train = pd.concat(
        [train[features], synthetic[features]],
        ignore_index=True,
    )

    y_train = pd.concat(
        [train["label"], synthetic["label"]],
        ignore_index=True,
    )

    X_val = validation[features]
    y_val = validation["label"]

    print("=== TRAINING DATA ===")
    print("Original:", len(train))
    print("Synthetic benign:", len(synthetic))
    print("Augmented total:", len(X_train))

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining experimental Random Forest...")
    model.fit(X_train, y_train)

    baseline_model = baseline["model"]

    baseline_class = list(baseline_model.classes_).index(1)
    experimental_class = list(model.classes_).index(1)

    baseline_probabilities = baseline_model.predict_proba(
        X_val
    )[:, baseline_class]

    experimental_probabilities = model.predict_proba(
        X_val
    )[:, experimental_class]

    baseline_result = evaluate(
        y_val,
        baseline_probabilities,
        baseline["threshold"],
    )

    selected, threshold_table = select_threshold(
        y_val,
        experimental_probabilities,
    )

    OUTPUT.mkdir(parents=True, exist_ok=True)

    threshold_table.to_csv(
        OUTPUT / "experimental_thresholds.csv",
        index=False,
    )

    print("\n=== BASELINE MODEL ===")
    print(pd.Series(baseline_result).round(4).to_string())

    print("\n=== AUGMENTED MODEL ===")

    if selected is None:
        print("No threshold meets 85% recall.")
        print("Experimental model not saved.")
        return

    print(selected.round(4).to_string())

    low_activity = (
        (validation["label"] == 0)
        & (validation["file_activity_total"] <= 10)
    ).to_numpy()

    print("\n=== LOW-ACTIVITY BENIGN FALSE POSITIVES ===")

    for name, probabilities, threshold in [
        ("Baseline", baseline_probabilities, baseline["threshold"]),
        ("Augmented", experimental_probabilities, selected["threshold"]),
    ]:
        fp = (
            probabilities[low_activity] >= threshold
        ).sum()

        total = low_activity.sum()

        print(
            f"{name}: {fp}/{total} "
            f"({100 * fp / total:.2f}%)"
        )

    live = pd.DataFrame([{
        "changed_file_count": 0,
        "file_access_breadth": 5,
        "directory_traversal_breadth": 1,
        "file_creation_count": 5,
        "file_deletion_count": 0,
        "extension_diversity": 1,
        "file_activity_total": 10,
    }])[features]

    print("\n=== HARMLESS LIVE TEST ===")

    print(
        "Baseline score:",
        round(
            baseline_model.predict_proba(live)[0, baseline_class],
            4,
        ),
    )

    print(
        "Augmented score:",
        round(
            model.predict_proba(live)[0, experimental_class],
            4,
        ),
    )

    joblib.dump(
        {
            "model": model,
            "feature_columns": features,
            "threshold": float(selected["threshold"]),
            "dataset": "RanDS + 200 experimental synthetic benign",
            "split_method": "grouped",
            "selection_dataset": "validation",
            "random_state": 42,
        },
        EXPERIMENTAL_MODEL,
    )

    print("\nExperimental model saved:", EXPERIMENTAL_MODEL)
    print("Original model unchanged.")


if __name__ == "__main__":
    main()
