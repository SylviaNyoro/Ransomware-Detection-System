#!/bin/bash
# Benign demo: perform ordinary document edits and renames
# while keeping the real Python process alive and its files open.

cd "$(dirname "$0")" || exit 1

python3 - <<'PY'
import os
import time
from pathlib import Path

d = Path("data/decoy/work")
folders = "abcdef"

for n in folders:
    (d / n).mkdir(parents=True, exist_ok=True)

print(f"[benign] Actual process PID: {os.getpid()}", flush=True)

# Open and edit documents, keeping their handles open.
files = {}
for n in folders:
    path = d / n / "f.txt"
    f = open(path, "w+")
    f.write("Routine document edit.\n")
    f.flush()
    files[n] = f

print("[benign] Six documents are open; allowing the watcher to observe them.", flush=True)
time.sleep(2.5)

# Rename two files while their original handles remain open.
for n in "ab":
    source = d / n / "f.txt"
    destination = d / n / "f.md"

    if source.exists():
        source.rename(destination)
        print(
            f"[benign] Renamed {source} -> {destination}; PID={os.getpid()}",
            flush=True,
        )
        # Give the watcher time to refresh its process snapshot.
        time.sleep(1.5)

for f in files.values():
    f.close()

time.sleep(2)
print("[benign] Done. Check the dashboard event log and PID values.", flush=True)
PY
