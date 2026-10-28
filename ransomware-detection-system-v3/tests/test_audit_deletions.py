"""Tests for Linux audit-backed file deletion attribution."""

from src.monitor.audit_attribution import parse_audit_deletions
from src.monitor.audit_reader import AuditRenameReader


def make_record(
    event_id=100,
    pid=16761,
    syscall=87,
    success="yes",
    path="data/decoy/feature_validation/test.txt",
):
    timestamp = "1792934108.099"

    return "\n".join([
        (
            f'type=SYSCALL msg=audit({timestamp}:{event_id}): '
            f'arch=c000003e syscall={syscall} success={success} '
            f'pid={pid}'
        ),
        (
            f'type=CWD msg=audit({timestamp}:{event_id}): '
            'cwd="/root/ransomware-detection-system-v3"'
        ),
        (
            f'type=PATH msg=audit({timestamp}:{event_id}): '
            f'item=1 name="{path}" nametype=DELETE'
        ),
    ])


def test_parse_successful_unlink():
    operations = parse_audit_deletions(make_record())

    assert len(operations) == 1
    assert operations[0].pid == 16761
    assert operations[0].syscall == "delete"
    assert operations[0].source_path.endswith(
        "/data/decoy/feature_validation/test.txt"
    )


def test_parse_successful_unlinkat():
    operations = parse_audit_deletions(make_record(syscall=263))

    assert len(operations) == 1
    assert operations[0].pid == 16761


def test_reject_failed_deletion():
    assert parse_audit_deletions(
        make_record(success="no")
    ) == []


def test_reject_unrelated_syscall():
    assert parse_audit_deletions(
        make_record(syscall=257)
    ) == []


def test_reject_multiple_deleted_paths():
    record = make_record()
    record += (
        '\ntype=PATH msg=audit(1792934108.099:100): '
        'item=2 name="another.txt" nametype=DELETE'
    )

    assert parse_audit_deletions(record) == []


def test_attribute_deletion_returns_verified_pid(monkeypatch):
    reader = AuditRenameReader(max_wait_seconds=0)

    operations = parse_audit_deletions(make_record())

    monkeypatch.setattr(
        reader,
        "_read_operations",
        lambda operation_type="rename": operations,
    )

    monkeypatch.setattr(
        "src.monitor.audit_reader.time.time",
        lambda: 1792934108.099,
    )

    pid = reader.attribute_deletion(
        "/root/ransomware-detection-system-v3/"
        "data/decoy/feature_validation/test.txt"
    )

    assert pid == 16761


def test_attribute_deletion_rejects_conflicting_pids(monkeypatch):
    reader = AuditRenameReader(max_wait_seconds=0)

    operations = parse_audit_deletions(
        make_record(event_id=100, pid=16761)
        + "\n"
        + make_record(event_id=101, pid=99999)
    )

    monkeypatch.setattr(
        reader,
        "_read_operations",
        lambda operation_type="rename": operations,
    )

    monkeypatch.setattr(
        "src.monitor.audit_reader.time.time",
        lambda: 1792934108.099,
    )

    pid = reader.attribute_deletion(
        "/root/ransomware-detection-system-v3/"
        "data/decoy/feature_validation/test.txt"
    )

    assert pid == -1
