"""
Analyze three-outcome Random Forest classification.

Classes:
    Benign
    Uncertain
    Ransomware

Threshold selection uses validation data only.
The held-out test dataset is not accessed.
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd


DATASET = Path(
    "data/processed/rands_filesystem_features_50000.csv"
)

MANIFEST = Path(
    "results/rands_grouped/split_manifest.csv"
)

MODEL_PATH = Path(
    "models/rands_random_forest_filesystem.joblib"
)

OUTPUT_DIR = Path(
    "results/rands_three_outcomes"
)

LOWER_THRESHOLDS = np.round(
    np.arange(0.20, 0.601, 0.025),
    3,
)


def classify(probabilities, lower, upper):
    return np.where(
        probabilities < lower,
        "Benign",
        np.where(
            probabilities < upper,
            "Uncertain",
            "Ransomware",
        ),
    )


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    bundle = joblib.load(MODEL_PATH)

    model = bundle["model"]
    features = bundle["feature_columns"]
    upper = float(bundle["threshold"])

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

    validation = merged[
        merged["split"] == "validation"
    ].copy()

    X_val = validation[features]
    y_val = validation["label"].to_numpy()

    positive_index = list(
        model.classes_
    ).index(1)

    probabilities = model.predict_proba(
        X_val
    )[:, positive_index]

    rows = []

    for lower in LOWER_THRESHOLDS:
        if lower >= upper:
            continue

        predictions = classify(
            probabilities,
            lower,
            upper,
        )

        benign = predictions == "Benign"
        uncertain = predictions == "Uncertain"
        ransomware = predictions == "Ransomware"

        actual_benign = y_val == 0
        actual_ransomware = y_val == 1

        total = len(y_val)
        benign_total = actual_benign.sum()
        ransomware_total = actual_ransomware.sum()

        ransomware_missed = int(
            (actual_ransomware & benign).sum()
        )

        ransomware_uncertain = int(
            (actual_ransomware & uncertain).sum()
        )

        ransomware_detected = int(
            (actual_ransomware & ransomware).sum()
        )

        benign_uncertain = int(
            (actual_benign & uncertain).sum()
        )

        benign_false_alarms = int(
            (actual_benign & ransomware).sum()
        )

        rows.append({
            "lower_threshold": float(lower),
            "upper_threshold": upper,

            "benign_count": int(benign.sum()),
            "uncertain_count": int(uncertain.sum()),
            "ransomware_count": int(
                ransomware.sum()
            ),

            "uncertain_rate": float(
                uncertain.sum() / total
            ),

            "ransomware_missed": ransomware_missed,
            "ransomware_uncertain": ransomware_uncertain,
            "ransomware_detected": ransomware_detected,

            "ransomware_missed_rate": float(
                ransomware_missed / ransomware_total
            ),

            "ransomware_review_rate": float(
                (
                    ransomware_uncertain
                    + ransomware_detected
                ) / ransomware_total
            ),

            "benign_uncertain": benign_uncertain,
            "benign_false_alarms": benign_false_alarms,

            "benign_false_alarm_rate": float(
                benign_false_alarms / benign_total
            ),

            "benign_escalation_rate": float(
                (
                    benign_uncertain
                    + benign_false_alarms
                ) / benign_total
            ),
        })

    results = pd.DataFrame(rows)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        OUTPUT_DIR / "threshold_comparison.csv",
        index=False,
    )

    print("\n=== THREE-OUTCOME THRESHOLD COMPARISON ===")

    columns = [
        "lower_threshold",
        "upper_threshold",
        "uncertain_rate",
        "ransomware_missed_rate",
        "ransomware_review_rate",
        "benign_false_alarm_rate",
        "benign_escalation_rate",
    ]

    print(
        results[columns]
        .round(4)
        .to_string(index=False)
    )

    # Choose the smallest missed-ransomware rate,
    # subject to at most 20% uncertain outcomes.
    eligible = results[
        results["uncertain_rate"] <= 0.20
    ].copy()

    if eligible.empty:
        print(
            "\nNo candidate satisfies "
            "the 20% uncertainty limit."
        )
        print(
            "Review the full comparison before "
            "choosing thresholds."
        )
        return

    selected = eligible.sort_values(
        [
            "ransomware_missed_rate",
            "uncertain_rate",
        ],
        ascending=[True, True],
    ).iloc[0]

    selection = {
        "lower_threshold": float(
            selected["lower_threshold"]
        ),
        "upper_threshold": upper,
        "selection_dataset": "validation",
        "maximum_uncertain_rate": 0.20,
        "metrics": {
            key: float(selected[key])
            for key in columns[2:]
        },
    }

    with open(
        OUTPUT_DIR / "selected_thresholds.json",
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            selection,
            handle,
            indent=2,
        )

    print("\n=== SELECTED THREE-OUTCOME THRESHOLDS ===")

    for key, value in selection.items():
        print(f"{key}: {value}")

    print("\n=== SAVED ===")
    print(
        OUTPUT_DIR / "threshold_comparison.csv"
    )
    print(
        OUTPUT_DIR / "selected_thresholds.json"
    )


if __name__ == "__main__":
    main()
