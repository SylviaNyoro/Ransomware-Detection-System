"""
Seven filesystem features derived from Linux monitor events.

This module matches the RanDS model's feature names.

Important limitations:
- Watchdog does not reliably capture file reads.
- Linux events are measured over a monitoring window.
- RanDS features summarize complete sandbox executions.
- These differences require separate deployment validation.
"""

from pathlib import PurePosixPath
from typing import Sequence

from src.feature_engineering.features import (
    EventType,
    FileEvent,
)

from src.feature_engineering.rands_filesystem_features import (
    FEATURE_COLUMNS,
)


def normalize_linux_path(path: str) -> str:
    """Normalize a Linux filesystem path."""
    return str(PurePosixPath(path))


def extract_linux_features(
    events: Sequence[FileEvent],
) -> dict[str, int]:
    """Extract the seven model features from observed events."""

    changed = [
        event
        for event in events
        if event.event_type == EventType.MODIFIED
    ]

    created = [
        event
        for event in events
        if event.event_type == EventType.CREATED
    ]

    deleted = [
        event
        for event in events
        if event.event_type == EventType.DELETED
    ]

    # Watchdog-observable paths only.
    # This is NOT equivalent to RanDS read-access breadth.
    accessed_paths = {
        normalize_linux_path(event.path)
        for event in events
    }

    all_paths = []

    for event in events:
        all_paths.append(
            normalize_linux_path(event.path)
        )

        if (
            event.event_type == EventType.RENAMED
            and event.dest_path
        ):
            all_paths.append(
                normalize_linux_path(event.dest_path)
            )

    directories = {
        str(PurePosixPath(path).parent)
        for path in all_paths
    }

    extensions = {
        PurePosixPath(path).suffix.lower()
        for path in all_paths
        if PurePosixPath(path).suffix
    }

    # Count observable event notifications, not unique paths.
    # These counts are not directly equivalent to RanDS
    # sandbox report entry counts.
    features = {
        "changed_file_count": len(changed),
        "file_access_breadth": len(accessed_paths),
        "directory_traversal_breadth": len(directories),
        "file_creation_count": len(created),
        "file_deletion_count": len(deleted),
        "extension_diversity": len(extensions),
        "file_activity_total": len(events),
    }

    return {
        name: features[name]
        for name in FEATURE_COLUMNS
    }
