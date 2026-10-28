"""Compare SHA-256 file integrity snapshots."""

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "demo",
        choices=["benign", "quarantine", "ransomware"],
    )
    args = parser.parse_args()

    evidence = ROOT / "evidence"

    before = json.loads(
        (evidence / f"{args.demo}_before.json").read_text()
    )
    after = json.loads(
        (evidence / f"{args.demo}_after.json").read_text()
    )

    old = {f["path"]: f["sha256"] for f in before["files"]}
    new = {f["path"]: f["sha256"] for f in after["files"]}

    unchanged = sorted(
        p for p in old.keys() & new.keys()
        if old[p] == new[p]
    )
    modified = sorted(
        p for p in old.keys() & new.keys()
        if old[p] != new[p]
    )

    removed = set(old) - set(new)
    added = set(new) - set(old)

    # Match removed and added files with identical content hashes.
    added_by_hash = {}
    for path in sorted(added):
        added_by_hash.setdefault(new[path], []).append(path)

    renamed = []
    for path in sorted(removed):
        matches = added_by_hash.get(old[path], [])
        if matches:
            destination = matches.pop(0)
            renamed.append({
                "from": path,
                "to": destination,
                "sha256": old[path],
            })
            added.remove(destination)
            removed.remove(path)

    summary = {
        "demo": args.demo,
        "before_file_count": len(old),
        "after_file_count": len(new),
        "unchanged_count": len(unchanged),
        "modified_count": len(modified),
        "renamed_count": len(renamed),
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged": unchanged,
        "modified": modified,
        "renamed": renamed,
        "added": sorted(added),
        "removed": sorted(removed),
    }

    output = evidence / f"{args.demo}_comparison.json"
    output.write_text(json.dumps(summary, indent=2))

    print(f"\n=== {args.demo.upper()} INTEGRITY REPORT ===")
    for key in [
        "before_file_count",
        "after_file_count",
        "unchanged_count",
        "modified_count",
        "renamed_count",
        "added_count",
        "removed_count",
    ]:
        print(f"{key}: {summary[key]}")

    print(f"Saved: {output}")


if __name__ == "__main__":
    main()
