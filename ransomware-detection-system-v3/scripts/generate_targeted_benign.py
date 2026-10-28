"""Generate 200 experimental benign filesystem feature vectors."""

from pathlib import Path

import numpy as np
import pandas as pd

DATASET = Path("data/processed/rands_filesystem_features_50000.csv")
MANIFEST = Path("results/rands_grouped/split_manifest.csv")
OUTPUT = Path("data/processed/targeted_benign_synthetic_200.csv")

FEATURES = [
    "changed_file_count",
    "file_access_breadth",
    "directory_traversal_breadth",
    "file_creation_count",
    "file_deletion_count",
    "extension_diversity",
    "file_activity_total",
]

TARGET = 200
rng = np.random.default_rng(42)


def valid(row):
    changed, accessed, directories, created, deleted, extensions, total = row

    if any(value < 0 for value in row):
        return False

    if total < changed + accessed + created + deleted:
        return False

    if directories > total or extensions > total:
        return False

    return True


def main():
    df = pd.read_csv(DATASET)
    manifest = pd.read_csv(MANIFEST)

    merged = df.merge(
        manifest[["sha256", "split"]],
        on="sha256",
        validate="one_to_one",
    )

    benign = merged[
        (merged["split"] == "train")
        & (merged["label"] == 0)
        & (merged["file_activity_total"] <= 20)
    ]

    print("Eligible benign training samples:", len(benign))

    if benign.empty:
        raise RuntimeError("No eligible benign training samples.")

    existing = {
        tuple(row)
        for row in merged[FEATURES].to_numpy()
    }

    generated = []
    seen = set()

    attempts = 0

    while len(generated) < TARGET and attempts < 100000:
        attempts += 1

        parent = benign.iloc[
            rng.integers(0, len(benign))
        ]

        row = parent[FEATURES].to_numpy(dtype=int).copy()

        # Add a small number of hypothetical file creations.
        additional = int(rng.integers(1, 7))

        row[3] += additional
        row[6] += additional

        # Optionally add access to newly created paths.
        added_access = int(rng.integers(0, additional + 1))
        row[1] += added_access
        row[6] += added_access

        # Introduce a limited number of new directories/extensions.
        row[2] += int(rng.integers(0, 2))
        row[5] += int(rng.integers(0, 2))

        key = tuple(row)

        if not valid(row):
            continue

        if key in existing or key in seen:
            continue

        seen.add(key)
        generated.append(row.tolist())

    if len(generated) != TARGET:
        raise RuntimeError(
            f"Generated only {len(generated)}/{TARGET} samples."
        )

    result = pd.DataFrame(generated, columns=FEATURES)
    result["label"] = 0
    result["source"] = "synthetic_targeted_benign"

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    print("\n=== SYNTHETIC DATASET CREATED ===")
    print("Samples:", len(result))
    print("Benign:", (result["label"] == 0).sum())
    print("Unique vectors:", len(result[FEATURES].drop_duplicates()))
    print("Output:", OUTPUT)

    print("\n=== FEATURE SUMMARY ===")
    print(result[FEATURES].describe().round(2).to_string())


if __name__ == "__main__":
    main()
