"""Generate SHA-256 integrity reports for demonstration directories."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIRECTORIES = {
    "benign": ROOT / "data/decoy/final_benign_demo",
    "quarantine": ROOT / "data/decoy/final_quarantine_demo",
    "ransomware": ROOT / "data/decoy/final_ransomware_classification_demo",
}


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("demo", choices=DIRECTORIES)
    parser.add_argument("stage", choices=["before", "after"])
    args = parser.parse_args()

    directory = DIRECTORIES[args.demo]
    records = []

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue

        stat = path.stat()

        records.append({
            "path": str(path.relative_to(directory)),
            "size_bytes": stat.st_size,
            "sha256": sha256(path),
        })

    report = {
        "demo": args.demo,
        "stage": args.stage,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "directory": str(directory),
        "file_count": len(records),
        "files": records,
    }

    output = ROOT / "evidence" / f"{args.demo}_{args.stage}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))

    print(f"Report: {output}")
    print(f"Files: {len(records)}")
    print(f"Timestamp: {report['timestamp_utc']}")


if __name__ == "__main__":
    main()
