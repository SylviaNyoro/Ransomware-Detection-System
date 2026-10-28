"""Generate harmless filesystem activity for live model validation."""

from pathlib import Path
import time

BASE = Path("data/decoy/validation")
BASE.mkdir(parents=True, exist_ok=True)


def prepare(name):
    folder = BASE / name
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def normal_activity():
    print("\nTEST 1: Normal file activity")
    folder = prepare("normal")

    for i in range(3):
        (folder / f"document_{i}.txt").write_text(
            "Normal document content"
        )
        time.sleep(1)

    print("Normal activity completed.")


def frequent_creation():
    print("\nTEST 2: Frequent file creation")
    folder = prepare("creation")

    for i in range(15):
        (folder / f"document_{i}.txt").write_text(
            "Harmless test content"
        )
        time.sleep(0.1)

    print("Frequent creation completed.")


def extension_changes():
    print("\nTEST 3: File extension changes")
    folder = prepare("extensions")

    for i in range(10):
        original = folder / f"sample_{i}.txt"
        original.write_text("Harmless sample")
        original.rename(folder / f"sample_{i}.test")
        time.sleep(0.1)

    print("Extension changes completed.")


if __name__ == "__main__":
    normal_activity()
    time.sleep(12)

    frequent_creation()
    time.sleep(12)

    extension_changes()
    time.sleep(12)

    print("\nAll validation tests completed.")
    print("Review the dashboard detection history.")
