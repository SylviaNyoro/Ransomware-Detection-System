"""Capture file-integrity evidence before a controlled TERMINATE demonstration."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "data/decoy/final_ransomware_classification_demo"
CONTROL_DIR = ROOT / "data/decoy/terminate_integrity_controls"
EVIDENCE_DIR = ROOT / "evidence"

EXTENSIONS = (
    ".txt", ".csv", ".json", ".log",
    ".md", ".xml", ".ini", ".cfg",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(directory):
    return {
        str(path.relative_to(ROOT)): {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def main():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)

    # Prepare exactly the files used by the existing demonstration.
    for directory_number in range(12):
        folder = DEMO_DIR / f"folder_{directory_number:02d}"
        folder.mkdir(parents=True, exist_ok=True)

        for file_number, extension in enumerate(EXTENSIONS):
            path = folder / f"sample_{file_number:02d}{extension}"

            if not path.exists():
                path.write_text(
                    f"Harmless demonstration file {file_number}\n",
                    encoding="utf-8",
                )

    # Separate files that must remain unchanged.
    for index in range(5):
        path = CONTROL_DIR / f"control_{index:02d}.txt"
        path.write_text(
            f"Unmodified integrity control {index}\n",
            encoding="utf-8",
        )

    result = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "TERMINATE pre-execution integrity baseline",
        "demo_files": snapshot(DEMO_DIR),
        "control_files": snapshot(CONTROL_DIR),
    }

    output = EVIDENCE_DIR / "terminate_integrity_before.json"

    output.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )

    print("========== TERMINATE INTEGRITY BASELINE ==========")
    print(f"Demonstration files: {len(result['demo_files'])}")
    print(f"Control files: {len(result['control_files'])}")
    print(f"Baseline saved: {output}")


if __name__ == "__main__":
    main()
