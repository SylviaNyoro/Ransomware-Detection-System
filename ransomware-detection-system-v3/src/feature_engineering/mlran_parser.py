"""
MLRan raw-report parser (proposal Ch. 3.6).

Built directly against MLRan's public repo (github.com/faithfulco/mlran),
specifically the report schema used by its own
`4_cuckoo_parser_scripts/3_file_operations_parser.py` and
`4_directory_operations_parser.py`.

Each raw report is a Cuckoo Sandbox `report.json` file named
`<sample_id>.json`. The fields this module reads are under
`report["behavior"]["summary"]`:

    file_created, file_recreated  -> treated as FileEvent CREATED
    file_written                  -> treated as FileEvent MODIFIED
    file_deleted                  -> treated as FileEvent DELETED
    file_opened                   -> treated as FileEvent OPENED

NOTE on renames: the 20 example reports bundled with MLRan do not expose
an explicit "file renamed" summary key (older Cuckoo behavior logs don't
consistently emit one either). Extension Change Rate is therefore computed
the same way for both this offline pipeline and the live monitor: from the
extensions of CREATED/MODIFIED paths against `common_extensions`, per
`compute_features()`. If a future MLRan release or Cuckoo version exposes
explicit move/rename events, they can be added as RENAMED FileEvents
without changing compute_features() itself.

Ground-truth labels come from `2_collected_samples_metadata/
mlran_dataset_metadata.csv`, column `sample_type` (1 = ransomware,
0 = goodware) -- this already matches the proposal's label convention
(benign = 0, ransomware = 1).

IMPORTANT DATA-AVAILABILITY NOTE (found while building this module):
MLRan's public repo currently ships only 20 example raw reports for
demonstration/testing (`4_cuckoo_parser_scripts/json_reports/`). Per the
repo's own `5_mlran_dataset/README.md`, "The full MLRan dataset,
containing all features, will be released after the paper is accepted
for publication." The metadata CSV lists ~4,880 samples (2,330
ransomware / 2,550 goodware), but only the 20 bundled reports have raw
per-sample logs available today. This module works correctly against
however many raw reports you have -- it just can't train a full-scale
classifier until more are released or an alternative source is used.
"""

import csv
import json
from pathlib import Path

import pandas as pd

from src.feature_engineering.features import EventType, FileEvent, compute_features

# Cuckoo behavior.summary key -> our EventType
_EVENT_KEY_MAP = {
    "file_created": EventType.CREATED,
    "file_recreated": EventType.CREATED,
    "file_written": EventType.MODIFIED,
    "file_deleted": EventType.DELETED,
    "file_opened": EventType.OPENED,
}


def load_labels(metadata_csv: str) -> dict[str, int]:
    """Read sample_id -> label (0=benign, 1=ransomware) from MLRan's
    mlran_dataset_metadata.csv (column: sample_type)."""
    labels = {}
    with open(metadata_csv, newline="") as f:
        for row in csv.DictReader(f):
            labels[row["sample_id"]] = int(row["sample_type"])
    return labels


def extract_events_from_report(report_path: str) -> list[FileEvent]:
    """Read one raw Cuckoo report.json and return its file-system events
    as FileEvent objects, ready for compute_features()."""
    with open(report_path) as f:
        report = json.load(f)

    summary = report.get("behavior", {}).get("summary", {})

    events: list[FileEvent] = []
    for summary_key, event_type in _EVENT_KEY_MAP.items():
        for path in summary.get(summary_key, []):
            events.append(FileEvent(path=path, event_type=event_type))
    return events


def parse_mlran_sample(
    sample_id: str,
    report_path: str,
    common_extensions: list[str],
    label: int | None = None,
) -> dict:
    """Parse one MLRan raw Cuckoo report into a single feature row."""
    events = extract_events_from_report(report_path)
    fv = compute_features(events, common_extensions)
    row = {"sample_id": sample_id, **fv.as_dict()}
    if label is not None:
        row["label"] = label
    return row


def build_dataset(
    raw_reports_dir: str,
    metadata_csv: str,
    common_extensions: list[str],
) -> pd.DataFrame:
    """Iterate over every raw report present in raw_reports_dir, join it
    against the metadata_csv labels, and build the labeled feature
    DataFrame described in Ch. 3.6 (Table 3.1: modification_frequency,
    extension_change_rate, file_access_breadth, label).

    Only samples that have BOTH a raw report on disk AND a label in the
    metadata CSV are included -- see the data-availability note in the
    module docstring for why that may be a small subset today.
    """
    labels = load_labels(metadata_csv)

    rows = []
    skipped_no_label = []
    for report_file in sorted(Path(raw_reports_dir).glob("*.json")):
        sample_id = report_file.stem
        label = labels.get(sample_id)
        if label is None:
            skipped_no_label.append(sample_id)
            continue
        rows.append(
            parse_mlran_sample(sample_id, str(report_file), common_extensions, label)
        )

    if skipped_no_label:
        print(
            f"[mlran_parser] skipped {len(skipped_no_label)} report(s) with no "
            f"matching label in metadata CSV: {skipped_no_label}"
        )

    return pd.DataFrame(rows, columns=[
        "sample_id",
        "modification_frequency",
        "extension_change_rate",
        "file_access_breadth",
        "label",
    ])


if __name__ == "__main__":
    import yaml

    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    df = build_dataset(
        raw_reports_dir=f"{cfg['paths']['raw_mlran_dir']}/json_reports",
        metadata_csv=f"{cfg['paths']['raw_mlran_dir']}/mlran_dataset_metadata.csv",
        common_extensions=cfg["features"]["common_extensions"],
    )
    out_path = cfg["paths"]["processed_dataset"]
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows to {out_path}")
    print(df["label"].value_counts())
