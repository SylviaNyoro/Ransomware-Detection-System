"""
Manual demonstration of the seven-feature Linux filesystem monitor.

Displays observed filesystem features without running predictions
or taking any response actions.
"""

import os
import signal
import time

import yaml

from src.monitor.watcher import start_monitor


def main():
    with open("config.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    monitor_cfg = cfg["monitor"]

    watched = monitor_cfg["watched_directories"]

    for directory in watched:
        os.makedirs(directory, exist_ok=True)

    def on_features(pid, features):
        print(
            f"[pid={pid}] {features}",
            flush=True,
        )

    observer, stop_event = start_monitor(
        watched_directories=watched,
        common_extensions=cfg["features"]["common_extensions"],
        poll_interval_seconds=monitor_cfg["poll_interval_seconds"],
        window_seconds=monitor_cfg["window_seconds"],
        min_events=monitor_cfg["min_events"],
        enable_audit_attribution=monitor_cfg[
            "enable_audit_attribution"
        ],
        on_features=on_features,
    )

    print(
        f"Watching {watched} "
        f"(window={monitor_cfg['window_seconds']}s, "
        f"min_events={monitor_cfg['min_events']})",
        flush=True,
    )

    print("Feature observation only. Press Ctrl+C to stop.")

    try:
        while observer.is_alive():
            time.sleep(0.5)

    except KeyboardInterrupt:
        pass

    finally:
        stop_event.set()
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
