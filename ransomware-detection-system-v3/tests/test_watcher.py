import time

from src.feature_engineering.features import EventType, FileEvent
from src.monitor.watcher import UNKNOWN_PID, LiveAggregator, ProcessAttributor

COMMON_EXT = [".txt", ".docx"]


def test_process_attributor_unknown_when_no_match():
    attributor = ProcessAttributor(refresh_interval_seconds=100)  # never refresh mid-test
    # No process on this machine has this exact fake path open.
    pid = attributor.attribute("/definitely/not/a/real/open/file/xyz123.bin")
    assert pid == UNKNOWN_PID


def test_process_attributor_finds_self_open_file(tmp_path):
    # Open a real file and keep the handle open so psutil can see it.
    f = tmp_path / "held_open.txt"
    handle = open(f, "w")
    try:
        attributor = ProcessAttributor(refresh_interval_seconds=0)  # always refresh
        pid = attributor.attribute(str(f))
        assert pid == __import__("os").getpid()
    finally:
        handle.close()


def test_live_aggregator_computes_features_per_pid():
    agg = LiveAggregator(COMMON_EXT, window_seconds=60)
    agg.handle_event(101, FileEvent(path="/a/b/report.txt", event_type=EventType.CREATED))
    agg.handle_event(101, FileEvent(path="/a/c/report.locked", event_type=EventType.CREATED))
    agg.handle_event(202, FileEvent(path="/x/y/notes.docx", event_type=EventType.OPENED))

    results = agg.poll()
    assert set(results.keys()) == {101, 202}
    assert results[101].modification_frequency == 2
    assert results[101].extension_change_rate == 1  # .locked is unusual
    assert results[202].modification_frequency == 0  # only opened, not created/modified


def test_live_aggregator_prunes_events_outside_window():
    agg = LiveAggregator(COMMON_EXT, window_seconds=0.05)
    agg.handle_event(
        1,
        FileEvent(path="/a/old.txt", event_type=EventType.CREATED),
        timestamp=time.time() - 10,  # far outside the window
    )
    results = agg.poll()
    assert 1 not in results  # stale event should have been pruned and pid dropped
