"""Integration test for seven-feature live filesystem monitoring."""

import time

import pytest

pytest.importorskip("watchdog")

from src.monitor.watcher import start_monitor
from src.feature_engineering.rands_filesystem_features import FEATURE_COLUMNS


COMMON_EXT = [".txt"]


@pytest.mark.integration
def test_start_monitor_detects_real_file_activity(tmp_path):
    """Verify Watchdog produces seven features from real filesystem events."""

    captured = []

    observer, stop_event = start_monitor(
        watched_directories=[str(tmp_path)],
        common_extensions=COMMON_EXT,
        poll_interval_seconds=0.2,
        window_seconds=5,
        on_features=lambda pid, features: captured.append(
            (pid, features)
        ),
    )

    try:
        # Harmless filesystem activity in pytest's temporary directory.
        for i in range(5):
            original = tmp_path / f"file{i}.txt"
            renamed = tmp_path / f"file{i}.locked"

            original.write_text("hello")
            original.rename(renamed)

        deadline = time.time() + 5

        while time.time() < deadline:
            if captured and any(
                features["file_creation_count"] > 0
                and features["extension_diversity"] >= 2
                for _, features in captured
            ):
                break

            time.sleep(0.2)

    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)

    assert captured, "No filesystem features were captured."

    for pid, features in captured:
        assert isinstance(features, dict)
        assert set(features) == set(FEATURE_COLUMNS)

    assert any(
        features["file_creation_count"] > 0
        for _, features in captured
    ), "Expected file creation activity."

    assert any(
        features["extension_diversity"] >= 2
        for _, features in captured
    ), "Expected multiple file extensions."

    assert any(
        features["file_activity_total"] > 0
        for _, features in captured
    ), "Expected filesystem activity."
