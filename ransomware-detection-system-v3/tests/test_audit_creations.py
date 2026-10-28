"""Regression tests for Linux Audit file creation attribution."""

from src.monitor.audit_attribution import parse_audit_creations


def make_record(
    pid=3319,
    syscall=257,
    success="yes",
    include_path=True,
    event_id=100,
):
    lines = [
        f'type=SYSCALL msg=audit(1792834692.100:{event_id}): '
        f'arch=c000003e syscall={syscall} success={success} '
        f'exit=3 pid={pid} key="ransomware_pid_test"',
        f'type=CWD msg=audit(1792834692.100:{event_id}): '
        'cwd="/tmp"',
    ]

    if include_path:
        lines.append(
            f'type=PATH msg=audit(1792834692.100:{event_id}): '
            'item=1 name="document.txt" nametype=CREATE'
        )

    return "\n".join(lines)


def test_successful_creation_extracts_pid():
    operations = parse_audit_creations(make_record())

    assert len(operations) == 1
    assert operations[0].pid == 3319
    assert operations[0].syscall == "create"
    assert operations[0].source_path == "/tmp/document.txt"


def test_failed_creation_is_ignored():
    assert parse_audit_creations(
        make_record(success="no")
    ) == []


def test_missing_path_is_ignored():
    assert parse_audit_creations(
        make_record(include_path=False)
    ) == []


def test_unrelated_syscall_is_ignored():
    assert parse_audit_creations(
        make_record(syscall=82)
    ) == []


def test_records_from_different_events_are_not_combined():
    first = make_record(include_path=False, event_id=100)

    second = (
        'type=PATH msg=audit(1792834692.101:101): '
        'item=1 name="document.txt" nametype=CREATE'
    )

    assert parse_audit_creations(first + "\n" + second) == []
