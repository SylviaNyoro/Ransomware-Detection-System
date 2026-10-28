from pathlib import Path
import time

BASE = Path("data/decoy/final_ransomware_classification_demo")

EXTENSIONS = [
    ".txt", ".csv", ".json", ".log",
    ".md", ".xml", ".ini", ".cfg",
]

print("Preparing harmless demonstration files...")

# Prepare files before the classification window.
for directory_number in range(12):
    folder = BASE / f"folder_{directory_number:02d}"
    folder.mkdir(parents=True, exist_ok=True)

    for file_number in range(8):
        extension = EXTENSIONS[file_number]
        path = folder / f"sample_{file_number:02d}{extension}"

        if not path.exists():
            path.write_text(
                f"Harmless demonstration file {file_number}\n"
            )

print("Waiting for previous monitoring events to expire...")
time.sleep(12)

print("Generating controlled filesystem activity...")

for directory_number in range(12):
    folder = BASE / f"folder_{directory_number:02d}"

    for file_number in range(8):
        extension = EXTENSIONS[file_number]
        path = folder / f"sample_{file_number:02d}{extension}"

        with path.open("a") as file:
            file.write("Harmless test update\n")

        time.sleep(0.025)

print("DEMONSTRATION COMPLETED")
print("96 harmless files updated across 12 directories.")

# Keep the harmless demonstration process available for
# monitoring and authorized response enforcement.
print("Waiting for monitoring and response verification...", flush=True)
time.sleep(30)
print("Monitoring period completed without termination.", flush=True)
