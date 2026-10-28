"""
Filesystem-focused behavioral features for RanDS.

Designed for the Linux endpoint ransomware detection
research prototype.

RanDS contains complete sandbox activity summaries,
not timestamped Linux monitoring windows.

Therefore, rates and actual extension rename counts
are deliberately excluded.
"""

from pathlib import PureWindowsPath


FEATURE_COLUMNS = [
    "changed_file_count",
    "file_access_breadth",
    "directory_traversal_breadth",
    "file_creation_count",
    "file_deletion_count",
    "extension_diversity",
    "file_activity_total",
]


FILE_KEYS = [
    "accessed_files",
    "created_files",
    "changed_files",
    "deleted_files",
]


def get_paths(record, key):
    """Return nonempty file paths from a RanDS field."""
    values = record.get(key, [])

    if not isinstance(values, list):
        return []

    return [
        value.strip()
        for value in values
        if isinstance(value, str) and value.strip()
    ]


def normalize_path(path):
    """Normalize Windows-style sandbox paths."""
    return str(PureWindowsPath(path)).lower()


def extract_features(record):
    """Extract filesystem behavior counts."""

    accessed = get_paths(record, "accessed_files")
    created = get_paths(record, "created_files")
    changed = get_paths(record, "changed_files")
    deleted = get_paths(record, "deleted_files")

    all_paths = accessed + created + changed + deleted

    unique_accessed = {
        normalize_path(path)
        for path in accessed
    }

    unique_directories = {
        str(PureWindowsPath(path).parent).lower()
        for path in all_paths
    }

    extensions = {
        PureWindowsPath(path).suffix.lower()
        for path in all_paths
        if PureWindowsPath(path).suffix
    }

    return {
        "changed_file_count": len(changed),
        "file_access_breadth": len(unique_accessed),
        "directory_traversal_breadth": len(
            unique_directories
        ),
        "file_creation_count": len(created),
        "file_deletion_count": len(deleted),
        "extension_diversity": len(extensions),
        "file_activity_total": len(all_paths),
    }
