"""Verify optional Linux Audit integration in the filesystem watcher."""

from unittest.mock import Mock

from src.feature_engineering.features import EventType
from src.monitor.watcher import RansomwareEventHandler


def make_handler(audit_pid, psutil_pid):
    attributor = Mock()
    attributor.attribute.return_value = psutil_pid

    aggregator = Mock()

    audit_reader = Mock()
    audit_reader.attribute_rename.return_value = audit_pid

    handler = RansomwareEventHandler(
        attributor,
        aggregator,
        audit_reader=audit_reader,
    )

    return handler, attributor, aggregator, audit_reader


def test_rename_uses_linux_audit_pid():
    handler, attributor, aggregator, audit = make_handler(
        audit_pid=2863,
        psutil_pid=-1,
    )

    handler._handle(
        "/tmp/original.txt",
        EventType.RENAMED,
        dest_path="/tmp/renamed.txt",
    )

    audit.attribute_rename.assert_called_once_with(
        "/tmp/original.txt",
        "/tmp/renamed.txt",
    )

    attributor.attribute.assert_not_called()

    args, _ = aggregator.handle_event.call_args
    assert args[0] == 2863
    assert args[1].process_id == 2863


def test_rename_falls_back_to_psutil():
    handler, attributor, aggregator, audit = make_handler(
        audit_pid=-1,
        psutil_pid=4321,
    )

    handler._handle(
        "/tmp/original.txt",
        EventType.RENAMED,
        dest_path="/tmp/renamed.txt",
    )

    attributor.attribute.assert_called_once_with(
        "/tmp/renamed.txt"
    )

    args, _ = aggregator.handle_event.call_args
    assert args[0] == 4321
    assert args[1].process_id == 4321


def test_creation_uses_linux_audit_pid():
    handler, attributor, aggregator, audit = make_handler(
        audit_pid=2863,
        psutil_pid=4321,
    )

    audit.attribute_creation.return_value = 2863

    handler._handle(
        "/tmp/document.txt",
        EventType.CREATED,
    )

    audit.attribute_creation.assert_called_once_with(
        "/tmp/document.txt"
    )
    audit.attribute_rename.assert_not_called()
    attributor.attribute.assert_not_called()

    args, _ = aggregator.handle_event.call_args
    assert args[0] == 2863
    assert args[1].process_id == 2863


def test_creation_falls_back_to_psutil():
    handler, attributor, aggregator, audit = make_handler(
        audit_pid=-1,
        psutil_pid=4321,
    )

    audit.attribute_creation.return_value = -1

    handler._handle(
        "/tmp/document.txt",
        EventType.CREATED,
    )

    audit.attribute_creation.assert_called_once_with(
        "/tmp/document.txt"
    )
    attributor.attribute.assert_called_once_with(
        "/tmp/document.txt"
    )

    args, _ = aggregator.handle_event.call_args
    assert args[0] == 4321
    assert args[1].process_id == 4321
