"""Regression tests for Linux Audit rename matching."""

from src.monitor.audit_attribution import (
    AuditFileOperation,
    match_rename_pid,
)


def operation(pid=2231, timestamp=100.0):
    return AuditFileOperation(
        timestamp=timestamp,
        pid=pid,
        syscall="rename",
        source_path="/tmp/original.txt",
        destination_path="/tmp/renamed.txt",
    )


def test_matching_paths_return_actual_pid():
    assert match_rename_pid(
        [operation()],
        "/tmp/original.txt",
        "/tmp/renamed.txt",
        event_timestamp=100.1,
    ) == 2231


def test_wrong_destination_is_rejected():
    assert match_rename_pid(
        [operation()],
        "/tmp/original.txt",
        "/tmp/unrelated.txt",
        event_timestamp=100.1,
    ) == -1


def test_old_audit_record_is_rejected():
    assert match_rename_pid(
        [operation()],
        "/tmp/original.txt",
        "/tmp/renamed.txt",
        event_timestamp=110.0,
    ) == -1


def test_ambiguous_matches_are_rejected():
    assert match_rename_pid(
        [operation(2231), operation(9999)],
        "/tmp/original.txt",
        "/tmp/renamed.txt",
        event_timestamp=100.1,
    ) == -1


def test_missing_destination_is_rejected():
    assert match_rename_pid(
        [operation()],
        "/tmp/original.txt",
        None,
        event_timestamp=100.1,
    ) == -1
