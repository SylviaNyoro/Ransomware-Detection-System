"""
DSTI dataset parser (fallback/supplementary source alongside MLRan, Ch. 3.6).

Source: github.com/DSTI-A20-RW/ransomware-preencryption-detector
(A20 cohort at Data ScienceTech Institute; goodware + malware samples run
through Cuckoo Sandbox, already parsed into a flat JSON per sample.)

This was investigated as a fallback after confirming that MLRan's full raw
corpus is not yet public (see mlran_parser.py docstring) and that
self-generating data is not an option for this project. Unlike MLRan's raw
Cuckoo report format, DSTI ships an already-parsed per-sample JSON at
`example-processed-datasets/preprocessed-json-samples/<class>-<hash>.json`
with this shape (only the parts this module reads are shown):

    {
        "file_class": {"class": "goodware"|"malware", ..., "class_label": 0|1},
        "file_operations": {
            "files_values": {
                "file_created": [...paths...],
                "file_written": [...paths...],
                "file_deleted": [...paths...],
                "file_opened":  [...paths...],
                ... (file_exists, file_failed, file_read -- not used here,
                     they don't correspond to a FileEvent type this study
                     tracks)
            }
        }
    }

`class_label` already matches this project's convention (0 = benign,
1 = malicious), consistent with MLRan's `sample_type` and the proposal's
Ch. 3.6 label definition.

IMPORTANT SCOPE CAVEAT (found while integrating this source): the DSTI
repo publicly ships only 12 example pre-parsed samples (6 goodware, 6
malware) and 20 raw report zips. Its own `generate_datasets.py` shows the
authors *did* collect a ransomware-specific subclass batch (IS_RANSOMWARE
flag, subclass_label=2), but none of the 12 public examples carry that
subclass -- they're all `subclass: "unspecified"` general malware. So
this source adds real, correctly-labeled goodware (which the 20 public
MLRan examples completely lack) but does not confirm ransomware-specific
behavior on its own. Treat samples from this source as "malicious,
unconfirmed-ransomware" until/unless the ransomware-labeled subset is
obtained directly from the authors.
"""

import json
from pathlib import Path

import pandas as pd

from src.feature_engineering.features import EventType, FileEvent, compute_features

_EVENT_KEY_MAP = {
    "file_created": EventType.CREATED,
    "file_written": EventType.MODIFIED,
    "file_deleted": EventType.DELETED,
    "file_opened": EventType.OPENED,
}


def extract_events_from_sample(sample_path: str) -> tuple[list[FileEvent], int]:
    """Read one DSTI pre-parsed sample JSON, returning its FileEvents and label."""
    with open(sample_path) as f:
        sample = json.load(f)

    label = sample["file_class"]["class_label"]
    files_values = sample.get("file_operations", {}).get("files_values", {})

    events: list[FileEvent] = []
    for summary_key, event_type in _EVENT_KEY_MAP.items():
        for path in files_values.get(summary_key, []):
            events.append(FileEvent(path=path, event_type=event_type))
    return events, label


def build_dataset(samples_dir: str, common_extensions: list[str]) -> pd.DataFrame:
    """Build the labeled feature DataFrame from every pre-parsed DSTI
    sample JSON in samples_dir, in the same schema as mlran_parser's
    build_dataset() output (sample_id, 3 features, label) so the two
    can be concatenated directly."""
    rows = []
    for sample_file in sorted(Path(samples_dir).glob("*.json")):
        events, label = extract_events_from_sample(str(sample_file))
        fv = compute_features(events, common_extensions)
        rows.append(
            {
                "sample_id": sample_file.stem,
                **fv.as_dict(),
                "label": label,
            }
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
        samples_dir="data/raw/dsti/preprocessed-json-samples",
        common_extensions=cfg["features"]["common_extensions"],
    )
    print(df)
    print(df["label"].value_counts())
