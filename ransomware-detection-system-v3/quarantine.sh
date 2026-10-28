#!/bin/bash
set -euo pipefail

cd ~/ransomware-detection-system-v3

exec python - <<'PY'
from pathlib import Path
import time

BASE = Path("data/decoy/final_quarantine_demo")
EXTENSIONS = [".txt", ".csv", ".log"]
FILES_PER_DIRECTORY = 4

print("Waiting for previous monitoring events to expire...", flush=True)
time.sleep(12)

files = []

print("Creating harmless demonstration files...", flush=True)

for directory_number in range(3):
    directory = BASE / f"group_{directory_number}"
    directory.mkdir(parents=True, exist_ok=True)

    for i in range(FILES_PER_DIRECTORY):
        extension = EXTENSIONS[directory_number]
        path = directory / f"sample_{time.time_ns()}_{i}{extension}"

        path.write_text(f"Harmless demonstration content {i}\n")
        files.append(path)

print(f"Created {len(files)} files across 3 directories.", flush=True)

print("Modifying demonstration files...", flush=True)

for path in files:
    with path.open("a") as file:
        file.write("Harmless demonstration update\n")

print("Deleting demonstration files...", flush=True)

for path in files:
    path.unlink()

print("Waiting for monitoring and enforcement...", flush=True)
time.sleep(20)
print("COMBINED QUARANTINE DEMONSTRATION COMPLETED", flush=True)
print("Files created: 12", flush=True)
print("Files modified: 12", flush=True)
print("Files deleted: 12", flush=True)
print("Directories used: 3", flush=True)
print("Extensions used: .txt, .csv, .log", flush=True)
PY
