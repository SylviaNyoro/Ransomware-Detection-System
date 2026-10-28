"""
Collect Linux filesystem behavior for feature compatibility testing.

Observation only:
- No model predictions
- No process suspension
- No process termination

The PID value -1 represents unattributed filesystem events.
"""

import argparse
import csv
import threading
import time

from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.feature_engineering.features import (
    EventType,
    FileEvent,
)

from src.feature_engineering.rands_filesystem_features import (
    FEATURE_COLUMNS,
)

from src.monitor.filesystem_aggregator import (
    FilesystemAggregator,
)


class ObservationHandler(FileSystemEventHandler):
    def __init__(self, aggregator):
        super().__init__()
        self.aggregator = aggregator

    def record(self, event, event_type):
        if event.is_directory:
            return

        file_event = FileEvent(
            path=event.src_path,
            event_type=event_type,
            dest_path=(
                event.dest_path
                if event_type == EventType.RENAMED
                else None
            ),
            process_id=None,
        )

        self.aggregator.handle_event(
            -1,
            file_event,
        )

    def on_created(self, event):
        self.record(event, EventType.CREATED)

    def on_modified(self, event):
        self.record(event, EventType.MODIFIED)

    def on_deleted(self, event):
        self.record(event, EventType.DELETED)

    def on_moved(self, event):
        self.record(event, EventType.RENAMED)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--directory",
        default="/tmp/rands_linux_observation",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
    )

    parser.add_argument(
        "--window",
        type=float,
        default=10.0,
    )

    args = parser.parse_args()

    directory = Path(args.directory)
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = Path(
        "results/linux_compatibility/"
        "linux_observations.csv"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    aggregator = FilesystemAggregator(
        window_seconds=args.window,
    )

    observer = Observer()
    observer.schedule(
        ObservationHandler(aggregator),
        str(directory),
        recursive=True,
    )

    rows = []

    observer.start()

    print("\n=== LINUX OBSERVATION ===")
    print("Directory:", directory)
    print("Duration:", args.duration)
    print("Window:", args.window)
    print("Monitoring started...", flush=True)

    start = time.monotonic()

    try:
        while (
            time.monotonic() - start
            < args.duration
        ):
            time.sleep(1)

            observations = aggregator.poll()

            for pid, features in observations.items():
                row = {
                    "timestamp": time.time(),
                    "pid": pid,
                    **features,
                }

                rows.append(row)

                print(
                    "Observed:",
                    features,
                    flush=True,
                )

    finally:
        observer.stop()
        observer.join()

        with open(
            output,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "timestamp",
                    "pid",
                    *FEATURE_COLUMNS,
                ],
            )

            writer.writeheader()
            writer.writerows(rows)

    print("\n=== OBSERVATION COMPLETE ===")
    print("Windows collected:", len(rows))
    print("Saved:", output)


if __name__ == "__main__":
    main()
