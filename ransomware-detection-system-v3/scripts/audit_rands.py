"""
Audit labeled RanDS behavioral JSON records.

Reads metadata and archive filenames without extracting
or executing any PE files.
"""

from pathlib import Path
import csv
import io
import zipfile

ARCHIVE = Path(
    "data/external/rands/"
    "RanDS_Behaviour_Activity_Dataset.zip"
)
PASSWORD = b"infected"


def main():
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)

    with zipfile.ZipFile(ARCHIVE) as z:
        names = z.namelist()

        json_hashes = {
            Path(name).stem.lower()
            for name in names
            if name.lower().endswith(".json")
        }

        print("Total behavioral JSON files:", len(json_hashes))

        class_hashes = {}

        for label, filename in [
            ("benign", "Benign.csv"),
            ("ransomware", "Ransomware.csv"),
        ]:
            matches = [
                name for name in names
                if Path(name).name.lower() == filename.lower()
            ]

            if len(matches) != 1:
                raise RuntimeError(
                    f"Expected one {filename}, "
                    f"found {len(matches)}"
                )

            with z.open(matches[0], pwd=PASSWORD) as f:
                reader = csv.DictReader(
                    io.TextIOWrapper(
                        f, encoding="utf-8-sig"
                    )
                )

                hashes = [
                    row["SHA256"].strip().lower()
                    for row in reader
                    if row.get("SHA256", "").strip()
                ]

            unique = set(hashes)
            matched = unique & json_hashes

            class_hashes[label] = matched

            print(f"\n=== {label.upper()} ===")
            print("Metadata rows:", len(hashes))
            print("Unique hashes:", len(unique))
            print("Matched JSON files:", len(matched))
            print(
                "Missing JSON files:",
                len(unique - json_hashes),
            )

        conflicts = (
            class_hashes["benign"]
            & class_hashes["ransomware"]
        )

        print("\nConflicting labels:", len(conflicts))

        for label in class_hashes:
            class_hashes[label] -= conflicts

        print("\n=== USABLE LABEL MATCHES ===")
        for label, hashes in class_hashes.items():
            print(label, len(hashes))

        print("\n=== 50,000-SAMPLE TARGET ===")

        requirements = {
            "benign": 15000,
            "ransomware": 35000,
        }

        possible = all(
            len(class_hashes[label]) >= needed
            for label, needed in requirements.items()
        )

        print(
            "35,000 ransomware + 15,000 benign:",
            "POSSIBLE" if possible else "INSUFFICIENT",
        )

        print(
            "\nNote: JSON contents have not yet been "
            "validated for usable activity."
        )


if __name__ == "__main__":
    main()
