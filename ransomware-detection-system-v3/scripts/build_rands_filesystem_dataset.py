"""
Build the revised filesystem-focused RanDS dataset.

Preserves:
- Original 50,000 SHA256 samples
- Existing benign/ransomware labels
- Existing grouped split compatibility

Does not overwrite the previous dataset.
"""

from pathlib import Path
import json
import zipfile

import pandas as pd

from src.feature_engineering.rands_filesystem_features import (
    FEATURE_COLUMNS,
    extract_features,
)


ARCHIVE = Path(
    "data/external/rands/"
    "RanDS_Behaviour_Activity_Dataset.zip"
)

ORIGINAL = Path(
    "data/processed/rands_features_50000.csv"
)

OUTPUT = Path(
    "data/processed/"
    "rands_filesystem_features_50000.csv"
)

PASSWORD = b"infected"


def main():
    original = pd.read_csv(ORIGINAL)

    if len(original) != 50000:
        raise ValueError(
            "Expected 50,000 original samples"
        )

    if original["sha256"].duplicated().any():
        raise ValueError(
            "Duplicate SHA256 in original dataset"
        )

    target_hashes = set(
        original["sha256"].astype(str).str.lower()
    )

    extracted = {}

    print("Reading RanDS archive...", flush=True)

    with zipfile.ZipFile(ARCHIVE) as archive:
        json_members = [
            member
            for member in archive.infolist()
            if member.filename.lower().endswith(".json")
        ]

        print(
            "JSON reports available:",
            len(json_members),
            flush=True,
        )

        for index, member in enumerate(
            json_members, start=1
        ):
            sha256 = Path(
                member.filename
            ).stem.lower()

            if sha256 not in target_hashes:
                continue

            with archive.open(
                member,
                pwd=PASSWORD,
            ) as handle:
                record = json.load(handle)

            extracted[sha256] = extract_features(
                record
            )

            if len(extracted) % 5000 == 0:
                print(
                    "Extracted:",
                    len(extracted),
                    "/ 50000",
                    flush=True,
                )

            if len(extracted) == len(target_hashes):
                break

    if len(extracted) != 50000:
        missing = target_hashes - set(extracted)

        raise RuntimeError(
            f"Missing {len(missing)} reports. "
            f"Examples: {list(missing)[:5]}"
        )

    features = pd.DataFrame.from_dict(
        extracted,
        orient="index",
    )

    features.index.name = "sha256"
    features = features.reset_index()

    dataset = original[
        ["sha256", "label", "source"]
    ].copy()

    dataset["sha256"] = (
        dataset["sha256"].astype(str).str.lower()
    )

    dataset = dataset.merge(
        features,
        on="sha256",
        how="left",
        validate="one_to_one",
    )

    if dataset[FEATURE_COLUMNS].isna().any().any():
        raise ValueError(
            "Missing extracted features"
        )

    dataset = dataset[
        ["sha256"] + FEATURE_COLUMNS + [
            "label",
            "source",
        ]
    ]

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataset.to_csv(
        OUTPUT,
        index=False,
    )

    print("\n=== NEW DATASET ===")
    print("Output:", OUTPUT)
    print("Shape:", dataset.shape)

    print("\n=== CLASS DISTRIBUTION ===")
    print(
        dataset["label"].value_counts().sort_index()
    )

    print("\n=== FEATURE SUMMARY ===")
    print(
        dataset[FEATURE_COLUMNS]
        .describe()
        .round(2)
        .to_string()
    )

    print("\n=== INTEGRITY CHECK ===")
    print(
        "Unique SHA256:",
        dataset["sha256"].nunique(),
    )
    print(
        "Original sample identities preserved:",
        set(dataset["sha256"])
        == target_hashes,
    )


if __name__ == "__main__":
    main()
