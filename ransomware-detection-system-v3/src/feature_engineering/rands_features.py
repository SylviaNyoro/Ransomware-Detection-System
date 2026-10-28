"""
Extract measurable file-behavior features from RanDS JSON.

Each JSON represents one sandbox-analyzed executable.
No raw executable files are accessed or executed.
"""

from pathlib import PureWindowsPath

FEATURE_COLUMNS = [
    "changed_file_count",
    "created_file_count",
    "deleted_file_count",
    "unique_accessed_files",
    "unique_file_extensions",
    "file_activity_total",
]

FILE_KEYS = [
    "accessed_files",
    "created_files",
    "deleted_files",
    "changed_files",
]


def normalize_paths(values):
    if not isinstance(values, list):
        raise ValueError("Expected a list of file paths")

    paths = []

    for value in values:
        if not isinstance(value, str):
            continue

        path = value.strip().strip('"')

        if path:
            paths.append(path)

    return paths


def extract_features(record):
    if not isinstance(record, dict):
        raise ValueError("Behavioral record must be a JSON object")

    activity = {}

    for key in FILE_KEYS:
        if key not in record:
            raise ValueError(f"Missing activity key: {key}")

        activity[key] = normalize_paths(record[key])

    all_paths = [
        path
        for key in FILE_KEYS
        for path in activity[key]
    ]

    extensions = set()

    for path in all_paths:
        suffix = PureWindowsPath(path).suffix.lower()

        if suffix:
            extensions.add(suffix)

    unique_accessed = {
        path.replace("/", "\\").lower()
        for path in activity["accessed_files"]
    }

    return {
        "changed_file_count": len(activity["changed_files"]),
        "created_file_count": len(activity["created_files"]),
        "deleted_file_count": len(activity["deleted_files"]),
        "unique_accessed_files": len(unique_accessed),
        "unique_file_extensions": len(extensions),
        "file_activity_total": len(all_paths),
    }
