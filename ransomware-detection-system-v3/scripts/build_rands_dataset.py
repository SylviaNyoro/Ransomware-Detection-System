"""
Build a 50,000-row RanDS behavioral feature dataset.

Target:
    35,000 ransomware (label 1)
    15,000 benign (label 0)

Only processed behavioral JSON and metadata CSV are read.
"""

from pathlib import Path
import csv
import io
import json
import random
import zipfile

import pandas as pd

from src.feature_engineering.rands_features import (
    FEATURE_COLUMNS,
    extract_features,
)

ARCHIVE = Path(
    "data/external/rands/"
    "RanDS_Behaviour_Activity_Dataset.zip"
)
OUTPUT = Path("data/processed/rands_features_50000.csv")

PASSWORD = b"infected"
SEED = 42

TARGETS = {
    0: 15000,
    1: 35000,
}


def load_hashes(z, filename):
    matches = [
        name for name in z.namelist()
        if Path(name).name.lower() == filename.lower()
    ]

    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one {filename}, found {len(matches)}"
        )

    with z.open(matches[0], pwd=PASSWORD) as f:
        reader = csv.DictReader(
            io.TextIOWrapper(f, encoding="utf-8-sig")
        )

        return sorted({
            row["SHA256"].strip().lower()
            for row in reader
            if row.get("SHA256", "").strip()
        })


def main():
    rng = random.Random(SEED)
    rows = []
    failures = []

    with zipfile.ZipFile(ARCHIVE) as z:
        json_paths = {
            Path(name).stem.lower(): name
            for name in z.namelist()
            if name.lower().endswith(".json")
        }

        classes = {
            0: load_hashes(z, "Benign.csv"),
            1: load_hashes(z, "Ransomware.csv"),
        }

        if set(classes[0]) & set(classes[1]):
            raise RuntimeError("Conflicting class labels")

        for label, hashes in classes.items():
            candidates = [
                sha for sha in hashes
                if sha in json_paths
            ]

            rng.shuffle(candidates)
            target = TARGETS[label]

            print(
                f"\nClass {label}: "
                f"{len(candidates)} candidates, "
                f"target {target}",
                flush=True,
            )

            accepted = 0

            for index, sha in enumerate(candidates, start=1):
                if accepted >= target:
                    break

                try:
                    with z.open(
                        json_paths[sha],
                        pwd=PASSWORD,
                    ) as f:
                        record = json.load(f)

                    features = extract_features(record)

                    # Exclude records with no observed file activity.
                    if features["file_activity_total"] == 0:
                        failures.append(
                            (sha, label, "no_file_activity")
                        )
                        continue

                    rows.append({
                        "sha256": sha,
                        **features,
                        "label": label,
                        "source": "rands",
                    })

                    accepted += 1

                except (
                    ValueError,
                    KeyError,
                    RuntimeError,
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                    OSError,
                ) as exc:
                    failures.append(
                        (sha, label, str(exc)[:200])
                    )

                if index % 5000 == 0:
                    print(
                        f"  Checked {index}, "
                        f"accepted {accepted}",
                        flush=True,
                    )

            print(
                f"Class {label}: accepted {accepted}/{target}",
                flush=True,
            )

            if accepted < target:
                raise RuntimeError(
                    f"Insufficient valid class {label} records: "
                    f"{accepted}/{target}. "
                    "No partial dataset saved."
                )

    df = pd.DataFrame(rows)

    if len(df) != 50000:
        raise AssertionError("Expected exactly 50,000 rows")

    if df["sha256"].duplicated().any():
        raise AssertionError("Duplicate SHA256 detected")

    if df[FEATURE_COLUMNS].isna().any().any():
        raise AssertionError("Missing feature values")

    df = df.sample(
        frac=1,
        random_state=SEED,
    ).reset_index(drop=True)

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(OUTPUT, index=False)

    failure_path = OUTPUT.with_name(
        "rands_excluded_records.csv"
    )

    pd.DataFrame(
        failures,
        columns=["sha256", "label", "reason"],
    ).to_csv(failure_path, index=False)

    print("\n=== DATASET CREATED ===")
    print("Output:", OUTPUT)
    print("Shape:", df.shape)
    print("Class distribution:")
    print(df["label"].value_counts().sort_index())
    print("Unique SHA256:", df["sha256"].nunique())
    print("Excluded candidates:", len(failures))

    print("\n=== FEATURE SUMMARY ===")
    print(df[FEATURE_COLUMNS].describe().to_string())

    print("\nDataset contains real RanDS behavioral records.")
    print("No synthetic augmentation was used.")


if __name__ == "__main__":
    main()
