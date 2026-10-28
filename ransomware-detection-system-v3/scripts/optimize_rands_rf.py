"""
Optimize RanDS Random Forest using the existing grouped split.

- No synthetic samples
- No new train/test split
- No test-set evaluation during model selection
- Compares feature subsets and RF hyperparameters
- Tunes thresholds using validation data only
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from src.feature_engineering.rands_features import FEATURE_COLUMNS


DATASET = Path("data/processed/rands_features_50000.csv")
MANIFEST = Path("results/rands_grouped/split_manifest.csv")
OUTPUT = Path("results/rands_optimization")
MODEL_PATH = Path("models/rands_random_forest_optimized.joblib")

SEED = 42
MIN_RECALL = 0.85
TARGET_FPR = 0.10

THRESHOLDS = np.round(
    np.arange(0.50, 0.801, 0.025),
    3,
)

FEATURE_SETS = {
    "all_six": list(FEATURE_COLUMNS),
    "without_total": [
        feature
        for feature in FEATURE_COLUMNS
        if feature != "file_activity_total"
    ],
}

CONFIGURATIONS = [
    {
        "max_depth": None,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 15,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 20,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 30,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": None,
        "min_samples_leaf": 5,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 20,
        "min_samples_leaf": 5,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 30,
        "min_samples_leaf": 5,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": None,
        "min_samples_leaf": 10,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 20,
        "min_samples_leaf": 10,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": 30,
        "min_samples_leaf": 10,
        "max_features": "sqrt",
        "class_weight": "balanced",
    },
    {
        "max_depth": None,
        "min_samples_leaf": 2,
        "max_features": 1.0,
        "class_weight": "balanced",
    },
    {
        "max_depth": 20,
        "min_samples_leaf": 5,
        "max_features": 1.0,
        "class_weight": "balanced",
    },
]


def metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
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
        "fpr": fp / (fp + tn),
        "fnr": fn / (fn + tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(
        parents=True, exist_ok=True
    )

    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

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
        raise ValueError("Dataset and manifest mismatch")

    train = merged[merged["split"] == "train"]
    validation = merged[
        merged["split"] == "validation"
    ]

    if len(train) != 32002 or len(validation) != 7999:
        raise ValueError(
            "Unexpected split sizes. "
            "Check your saved split manifest."
        )

    y_train = train["label"].to_numpy()
    y_val = validation["label"].to_numpy()

    results = []

    best = None
    best_model = None
    best_features = None

    total_models = (
        len(FEATURE_SETS) * len(CONFIGURATIONS)
    )

    counter = 0

    for feature_set_name, features in FEATURE_SETS.items():
        X_train = train[features]
        X_val = validation[features]

        for config_id, config in enumerate(
            CONFIGURATIONS, start=1
        ):
            counter += 1

            print(
                f"\n[{counter}/{total_models}] "
                f"Features={feature_set_name}, "
                f"Configuration={config_id}",
                flush=True,
            )

            model = RandomForestClassifier(
                n_estimators=200,
                random_state=SEED,
                n_jobs=-1,
                **config,
            )

            model.fit(X_train, y_train)

            probabilities = model.predict_proba(
                X_val
            )[:, list(model.classes_).index(1)]

            for threshold in THRESHOLDS:
                predictions = (
                    probabilities >= threshold
                ).astype(int)

                result = metrics(
                    y_val, predictions
                )

                row = {
                    "feature_set": feature_set_name,
                    "configuration": config_id,
                    "threshold": float(threshold),
                    **config,
                    **result,
                }

                results.append(row)

                # First prefer candidates satisfying both
                # recall and FPR requirements.
                feasible = (
                    result["recall"] >= MIN_RECALL
                    and result["fpr"] < TARGET_FPR
                )

                # Among feasible candidates, maximize F1.
                # If none is feasible, minimize FPR while
                # maintaining minimum recall.
                eligible = (
                    result["recall"] >= MIN_RECALL
                )

                if not eligible:
                    continue

                score = (
                    int(feasible),
                    result["f1_score"]
                    if feasible
                    else -result["fpr"],
                    result["recall"],
                )

                if best is None or score > best["score"]:
                    best = {
                        "score": score,
                        "row": row,
                    }
                    best_model = model
                    best_features = list(features)

    table = pd.DataFrame(results)

    table.to_csv(
        OUTPUT / "all_results.csv",
        index=False,
    )

    if best is None:
        raise RuntimeError(
            "No configuration met minimum recall."
        )

    selected = best["row"]

    print("\n=== BEST VALIDATION CONFIGURATION ===")

    for key in [
        "feature_set",
        "configuration",
        "threshold",
        "max_depth",
        "min_samples_leaf",
        "max_features",
        "class_weight",
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "fpr",
        "fnr",
    ]:
        print(f"{key}: {selected[key]}")

    print("\n=== TARGET CHECK ===")
    print(
        "Recall >= 85%:",
        selected["recall"] >= MIN_RECALL,
    )
    print(
        "FPR < 10%:",
        selected["fpr"] < TARGET_FPR,
    )

    bundle = {
        "model": best_model,
        "feature_columns": best_features,
        "threshold": float(
            selected["threshold"]
        ),
        "dataset": "RanDS",
        "split_method": "grouped",
        "selection_dataset": "validation",
        "random_state": SEED,
    }

    joblib.dump(bundle, MODEL_PATH)

    with open(
        OUTPUT / "best_configuration.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                "feature_columns": best_features,
                "selected": selected,
            },
            f,
            indent=2,
            default=lambda x: (
                x.item()
                if isinstance(x, np.generic)
                else str(x)
            ),
        )

    print("\n=== SAVED ===")
    print("Model:", MODEL_PATH)
    print(
        "Comparison:",
        OUTPUT / "all_results.csv",
    )
    print(
        "Best configuration:",
        OUTPUT / "best_configuration.json",
    )


if __name__ == "__main__":
    main()
