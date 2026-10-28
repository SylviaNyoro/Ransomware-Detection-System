"""
Check whether identical feature vectors appear across
the existing grouped train/validation/test assignments.

Read-only diagnostic.
"""

import pandas as pd

from src.feature_engineering.rands_filesystem_features import (
    FEATURE_COLUMNS,
)

DATASET = (
    "data/processed/"
    "rands_filesystem_features_50000.csv"
)

MANIFEST = (
    "results/rands_grouped/split_manifest.csv"
)


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        validate="one_to_one",
    )

    if len(merged) != len(df):
        raise ValueError(
            "Dataset and split manifest mismatch"
        )

    feature_sets = {
        "all_seven": FEATURE_COLUMNS,
        "without_total": [
            feature
            for feature in FEATURE_COLUMNS
            if feature != "file_activity_total"
        ],
    }

    for name, features in feature_sets.items():
        print(f"\n=== {name.upper()} ===")

        patterns = {}

        for split in [
            "train",
            "validation",
            "test",
        ]:
            subset = merged[
                merged["split"] == split
            ]

            patterns[split] = set(
                map(
                    tuple,
                    subset[features].to_numpy(),
                )
            )

        comparisons = [
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        ]

        for first, second in comparisons:
            overlap = len(
                patterns[first] & patterns[second]
            )

            print(
                f"{first}/{second}: {overlap}"
            )


if __name__ == "__main__":
    main()
