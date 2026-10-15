"""
Shared feature-computation logic for the Enterprise Ransomware Detection System.

Per proposal Ch. 3.6 ("Data Requirements"), a single feature-engineering
routine computes three aggregate features from a stream of file-system
events for one process/sample:

    1. Modification Frequency  - count of file-write / file-create events
    2. Extension Change Rate   - count of new/unusual extensions appearing
                                  among written/created files
    3. File Access Breadth     - count of unique parent directories touched
                                  across created, written, opened and
                                  deleted file paths

This module is deliberately shared between:
  - the offline MLRan pipeline (src/feature_engineering/mlran_parser.py),
    which replays historical Cuckoo Sandbox event logs through it, and
  - the live monitoring pipeline (src/monitor/watcher.py),
    which feeds it real Watchdog events as they happen.

Keeping one implementation guarantees training-time and inference-time
features stay consistent (proposal Ch. 3.6, final paragraph).
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable, Sequence


class EventType(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    OPENED = "opened"


@dataclass(frozen=True)
class FileEvent:
    """A single observed file-system event, from either MLRan replay or Watchdog."""

    path: str
    event_type: EventType
    # For renamed events, dest_path is the new path/extension.
    dest_path: str | None = None
    process_id: int | None = None
    timestamp: float | None = None


@dataclass(frozen=True)
class FeatureVector:
    modification_frequency: int
    extension_change_rate: int
    file_access_breadth: int

    def as_dict(self) -> dict:
        return {
            "modification_frequency": self.modification_frequency,
            "extension_change_rate": self.extension_change_rate,
            "file_access_breadth": self.file_access_breadth,
        }


def normalize_path(path: str) -> str:
    """MLRan/Cuckoo reports use Windows-style backslash paths; the live
    monitor will see POSIX paths. Normalizing to forward slashes lets one
    PurePosixPath-based implementation handle both consistently. Public
    because other modules (e.g. the live monitor's process attributor)
    need the same normalization for path matching."""
    return path.replace("\\", "/")


def _extension_of(path: str) -> str:
    return PurePosixPath(normalize_path(path)).suffix.lower()


def _parent_dir_of(path: str) -> str:
    return str(PurePosixPath(normalize_path(path)).parent)


def compute_features(
    events: Sequence[FileEvent],
    common_extensions: Iterable[str],
) -> FeatureVector:
    """
    Compute the three aggregate features for one process/sample's event window.

    Args:
        events: ordered or unordered file-system events for a single
            process (live pipeline) or sample (MLRan replay).
        common_extensions: extensions treated as "normal"; anything else
            seen on a create/write/rename counts toward extension_change_rate.

    Returns:
        FeatureVector with the three feature values for this window.
    """
    common = {ext.lower() for ext in common_extensions}

    modification_frequency = sum(
        1 for e in events if e.event_type in (EventType.CREATED, EventType.MODIFIED)
    )

    unusual_extensions_seen = set()
    for e in events:
        if e.event_type in (EventType.CREATED, EventType.MODIFIED):
            ext = _extension_of(e.path)
            if ext not in common:
                unusual_extensions_seen.add(ext)
        elif e.event_type == EventType.RENAMED and e.dest_path:
            ext = _extension_of(e.dest_path)
            if ext not in common:
                unusual_extensions_seen.add(ext)
    extension_change_rate = len(unusual_extensions_seen)

    relevant_events = (
        EventType.CREATED,
        EventType.MODIFIED,
        EventType.OPENED,
        EventType.DELETED,
    )
    touched_dirs = {
        _parent_dir_of(e.path) for e in events if e.event_type in relevant_events
    }
    # A rename touches both the old and new parent directory.
    touched_dirs |= {
        _parent_dir_of(e.dest_path)
        for e in events
        if e.event_type == EventType.RENAMED and e.dest_path
    }
    file_access_breadth = len(touched_dirs)

    return FeatureVector(
        modification_frequency=modification_frequency,
        extension_change_rate=extension_change_rate,
        file_access_breadth=file_access_breadth,
    )
