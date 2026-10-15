"""
Step 7 demonstration / testing harness (Ch. 3.7).

This is intentionally a safe, reproducible, headless harness:
- uses a temporary directory, not data/decoy, so it never interferes with
  a real monitoring session;
- loads the actual persisted model/scaler via the real LiveDetector
  (src/live_detection.py) -- the same class the GUI backend
  (src/gui/backend.py) uses in production, so this harness exercises the
  real classify-then-respond path, not a reimplementation of it;
- runs the real Watchdog monitor (src/monitor/watcher.py);
- creates synthetic ransomware-like FILE EVENTS only (plain file
  create/rename operations) -- no actual ransomware or malicious code is
  involved anywhere in this harness;
- runs in "observe" mode by default (enforce=False), so no real
  Terminate/Quarantine action is taken against any process during
  automated testing -- see config.yaml's response.mode and
  src/response/responder.py's enforce flag;
- measures reaction time directly (wall-clock time from a feature vector
  arriving to the response decision being made), for the Ch. 3.7
  operational metric.

Deliberately has NO dependency on src/gui/dashboard.py or
src/gui/backend.py: the dashboard needs a separate Python 3.14
environment (see README.md's Step 6), so the Step 7 harness must stay
runnable in the plain backend environment on its own, independent of
whether the GUI's environment is even set up.

Run from the project root:
    python -m scripts.end_to_end_demo
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import yaml

from src.live_detection import create_live_detector
from src.monitor.watcher import start_monitor


def run_demo(timeout_seconds: float = 8.0, enforce: bool = False) -> list[dict]:
    with open("config.yaml", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle)

    detector = create_live_detector(cfg)
    detector.response_mode = "enforce" if enforce else "observe"

    results: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="ransomware-demo-") as tmp:
        root = Path(tmp)
        (root / "a").mkdir()
        (root / "b").mkdir()
        (root / "c").mkdir()

        def on_features(pid, fv):
            start = time.perf_counter()
            result = detector.on_features(pid, fv)
            reaction_time_ms = (time.perf_counter() - start) * 1000
            results.append({**result, "reaction_time_ms": reaction_time_ms})

        observer, stop_event = start_monitor(
            watched_directories=[str(root)],
            common_extensions=cfg["features"]["common_extensions"],
            poll_interval_seconds=0.2,
            window_seconds=5,
            on_features=on_features,
        )

        try:
            # Safe simulation: no ransomware is used. These operations imitate
            # the filesystem pattern the detector is designed to observe
            # (rapid creation + rename to an unusual extension across
            # several directories).
            for index, folder in enumerate(("a", "b", "c")):
                source = root / folder / f"document{index}.txt"
                target = root / folder / f"document{index}.encrypted"
                source.write_text("DEMO DATA", encoding="utf-8")
                source.rename(target)

            deadline = time.time() + timeout_seconds
            while time.time() < deadline and not results:
                time.sleep(0.1)
        finally:
            stop_event.set()
            observer.stop()
            observer.join(timeout=5)

    return results


if __name__ == "__main__":
    rows = run_demo()
    print("\n--- End-to-end Step 7 results ---")
    if not rows:
        print("No classification arrived before timeout.")
    else:
        for row in rows:
            print(row)
