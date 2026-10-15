"""
Manual demo for the live monitor (Step 4). Run this, then create/edit/
rename files in the watched directory in another terminal and watch
feature vectors appear here in real time.

Usage:
    mkdir -p data/decoy
    python -m scripts.demo_monitor
    # in another terminal: touch data/decoy/test.txt && mv data/decoy/test.txt data/decoy/test.locked
"""

import signal
import time

import yaml

from src.monitor.watcher import start_monitor


def main():
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    watched = cfg["monitor"]["watched_directories"]
    common_ext = cfg["features"]["common_extensions"]
    poll_interval = cfg["monitor"]["poll_interval_seconds"]

    for d in watched:
        import os
        os.makedirs(d, exist_ok=True)

    def on_features(pid, fv):
        print(f"[pid={pid}] {fv.as_dict()}")

    observer, stop_event = start_monitor(
        watched_directories=watched,
        common_extensions=common_ext,
        poll_interval_seconds=poll_interval,
        on_features=on_features,
    )

    print(f"Watching {watched} -- Ctrl+C to stop.")

    def _shutdown(signum, frame):
        stop_event.set()
        observer.stop()

    signal.signal(signal.SIGINT, _shutdown)

    try:
        while observer.is_alive():
            time.sleep(0.5)
    finally:
        observer.join()


if __name__ == "__main__":
    main()
