import pytest
pytest.importorskip("watchdog")

import time

from src.monitor.watcher import start_monitor

COMMON_EXT = [".txt"]


def test_start_monitor_detects_real_file_activity(tmp_path):
    """End-to-end: a real Observer watching a real directory picks up
    real file writes and produces a FeatureVector via on_features."""
    captured = []

    observer, stop_event = start_monitor(
        watched_directories=[str(tmp_path)],
        common_extensions=COMMON_EXT,
        poll_interval_seconds=0.2,
        window_seconds=5,
        on_features=lambda pid, fv: captured.append((pid, fv)),
    )

    try:
        # Simulate "ransomware-like" activity: rapid creation of files
        # with an unusual extension, matching what compute_features()
        # should flag.
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_text("hello")
            (tmp_path / f"file{i}.txt").rename(tmp_path / f"file{i}.locked")

        # Give the OS + watchdog + poll loop time to catch up.
        deadline = time.time() + 5
        while time.time() < deadline and not captured:
            time.sleep(0.2)
    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)

    assert captured, "expected at least one FeatureVector to be captured"
    # At least one observed feature vector should show real signal:
    # multiple creates and an unusual extension.
    seen_modification = any(fv.modification_frequency > 0 for _, fv in captured)
    seen_extension_change = any(fv.extension_change_rate > 0 for _, fv in captured)
    assert seen_modification
    assert seen_extension_change
