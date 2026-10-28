"""Regression tests for the minimum filesystem event requirement."""

from src.feature_engineering.features import EventType, FileEvent
from src.monitor.filesystem_aggregator import FilesystemAggregator


def make_event(index):
    return FileEvent(
        path=f"/tmp/test_document_{index}.txt",
        event_type=EventType.CREATED,
    )


def test_fewer_than_ten_events_produces_no_detection():
    aggregator = FilesystemAggregator(
        window_seconds=10.0,
        min_events=10,
    )

    for i in range(9):
        aggregator.handle_event(12345, make_event(i))

    assert aggregator.poll() == {}


def test_tenth_event_produces_features():
    aggregator = FilesystemAggregator(
        window_seconds=10.0,
        min_events=10,
    )

    for i in range(10):
        aggregator.handle_event(12345, make_event(i))

    results = aggregator.poll()

    assert 12345 in results
    assert results[12345]["file_activity_total"] == 10


def test_unchanged_window_is_not_emitted_twice():
    aggregator = FilesystemAggregator(
        window_seconds=10.0,
        min_events=10,
    )

    for i in range(10):
        aggregator.handle_event(12345, make_event(i))

    assert 12345 in aggregator.poll()
    assert aggregator.poll() == {}
