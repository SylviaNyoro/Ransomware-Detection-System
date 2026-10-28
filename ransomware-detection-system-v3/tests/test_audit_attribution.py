"""Tests for Linux Audit rename PID attribution."""

from src.monitor.audit_attribution import parse_audit_records


def audit_event(event_id=26, pid=30131, success="yes",
                include_destination=True):
    lines = [
        f'type=SYSCALL msg=audit(1792834692.086:{event_id}): '
        f'arch=c000003e syscall=82 success={success} '
        f'exit=0 pid={pid} key="ransomware_pid_test"',
        f'type=CWD msg=audit(1792834692.086:{event_id}): '
        'cwd="/tmp"',
        f'type=PATH msg=audit(1792834692.086:{event_id}): '
        'item=2 name="original.txt" nametype=DELETE',
    ]

    if include_destination:
        lines.append(
            f'type=PATH msg=audit(1792834692.086:{event_id}): '
            'item=3 name="renamed.txt" nametype=CREATE'
        )

    return "\n".join(lines)


def test_successful_rename_extracts_actual_pid():
    operations = parse_audit_records(audit_event())

    assert len(operations) == 1
    assert operations[0].pid == 30131
    assert operations[0].syscall == "rename"
    assert operations[0].source_path == "/tmp/original.txt"
    assert operations[0].destination_path == "/tmp/renamed.txt"


def test_failed_rename_is_ignored():
    operations = parse_audit_records(
        audit_event(success="no")
    )
    assert operations == []


def test_incomplete_rename_is_ignored():
    operations = parse_audit_records(
        audit_event(include_destination=False)
    )
    assert operations == []


def test_unrelated_audit_events_are_not_combined():
    first = audit_event(
        event_id=26,
        include_destination=False,
    )

    second = "\n".join([
        'type=SYSCALL msg=audit(1792834692.087:27): '
        'arch=c000003e syscall=82 success=yes '
        'exit=0 pid=99999',
        'type=CWD msg=audit(1792834692.087:27): '
        'cwd="/tmp"',
        'type=PATH msg=audit(1792834692.087:27): '
        'item=3 name="renamed.txt" nametype=CREATE',
    ])

    assert parse_audit_records(first + "\n" + second) == []
