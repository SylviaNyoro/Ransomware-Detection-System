from pathlib import Path
import time

BASE = Path("data/decoy/feature_validation")
BASE.mkdir(parents=True, exist_ok=True)

print("Waiting for previous monitoring events to expire...")
time.sleep(12)

print("Creating 12 harmless files...")

files = []

for i in range(12):
    path = BASE / f"validation_{time.time_ns()}_{i}.txt"
    path.write_text(f"Harmless feature validation {i}\n")
    files.append(path)
    time.sleep(0.05)

print("Waiting 2 seconds...")
time.sleep(2)

print("Deleting the 12 test files...")

for path in files:
    path.unlink()
    time.sleep(0.05)

print("FEATURE VALIDATION COMPLETED")
print("12 files created and 12 files deleted.")
