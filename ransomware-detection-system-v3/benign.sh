#!/bin/bash

cd ~/ransomware-detection-system-v3 || exit 1

exec python - <<'PY'
from pathlib import Path
import time

directory = Path("data/decoy/final_benign_demo")

# Restore original filenames.
for i in range(10):
    original = directory / f"document_{i:02d}.txt"
    renamed = directory / f"renamed_document_{i:02d}.txt"

    if renamed.exists():
        renamed.rename(original)

# Clear the previous monitoring window.
print("Waiting for monitoring window to clear...")
time.sleep(12)

# Perform harmless file renaming.
for i in range(10):
    original = directory / f"document_{i:02d}.txt"
    renamed = directory / f"renamed_document_{i:02d}.txt"

    original.rename(renamed)
    time.sleep(0.1)

print("BENIGN DEMONSTRATION COMPLETED")
print("10 harmless files renamed.")
PY
