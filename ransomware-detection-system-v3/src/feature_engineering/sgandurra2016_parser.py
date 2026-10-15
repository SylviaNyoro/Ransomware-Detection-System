"""
Sgandurra et al. (2016) dataset parser -- the real fallback source
(Ch. 3.6), used in place of RansomNet after the RansomNet Zenodo archive
turned out to be too large to download/store practically.

Source: github.com/rissgrouphub/ransomwaredataset2016
Paper: Sgandurra, Munoz-Gonzalez, Mohsen, Lupu (2016), "Automated Dynamic
Analysis of Ransomware: Benefits, Limitations and use for Detection"
(arXiv:1609.03020) -- a real, peer-reviewed, widely-cited academic
dataset (31+ GitHub stars, cited by dozens of later ransomware-detection
papers, several of which this project's own literature review likely
already references).

WHY THIS SOURCE, CONCRETELY:
  - 1,524 real samples: 582 ransomware (11 families) + 942 goodware.
    Balanced enough to actually train and evaluate a classifier, unlike
    MLRan's 20 (all ransomware) or DSTI's 12 (general malware, not
    ransomware-confirmed).
  - Small and practical: RansomwareData.zip is ~500 KB; the extracted
    CSV is ~94 MB. No 46 GB download, no separate disk partition needed.
  - Already per-sample and per-feature, from real Cuckoo Sandbox dynamic
    analysis, with a `Label` column (1 = ransomware, 0 = goodware) that
    already matches this project's convention (same as MLRan's
    sample_type and DSTI's class_label).

DATA SHAPE (see VariableNames.txt for the full column dictionary):
    Column 1: sample ID
    Column 2: Label (1 = ransomware, 0 = goodware)
    Column 3: Ransomware family ID (0 = goodware; see README.txt)
    Columns 4+: one binary column per behavioral feature, named like
        "FILES:WRITTEN:<path>"
        "FILES:OPENED:<path>"
        "FILES:DELETED:<path>"
        "DIR:CREATED:<path>" / "DIR:ENUMERATED:<path>"
        "FILES_EXT:WRITTEN:<ext>" / etc.
        "API:<name>", "REG:<op>:<key>", "STR:<n>", "DROP:<ext>"
    A 1 means that exact path/behavior was observed for that sample.

This parser reconstructs FileEvents from the FILES:WRITTEN / FILES:OPENED
/ FILES:DELETED columns (there is no separate FILES:CREATED category in
this dataset -- WRITTEN covers both new and modified files, which is
consistent with how modification_frequency is defined: CREATED or
MODIFIED events both count) and runs them through the SAME
compute_features() used by mlran_parser.py and dsti_parser.py, so all
three sources produce directly comparable feature rows.

CAVEAT: this dataset is from Windows XP-era Cuckoo analysis (Feb 2016),
which is old and stylistically different from more modern samples (and
from MLRan's, which spans newer years per its metadata). Worth noting in
Ch. 3.6/3.7 as a limitation of the training data's age/representativeness,
even though it solves the scale and class-balance problem.
"""

from pathlib import Path

import pandas as pd

from src.feature_engineering.features import EventType, FileEvent, compute_features

_CATEGORY_TO_EVENT_TYPE = {
    "WRITTEN": EventType.MODIFIED,
    "OPENED": EventType.OPENED,
    "DELETED": EventType.DELETED,
}


def load_files_column_map(variable_names_path: str) -> dict[int, tuple[EventType, str]]:
    """Parse VariableNames.txt and return {csv_column_index (0-based):
    (EventType, path)} for every FILES:WRITTEN / FILES:OPENED /
    FILES:DELETED column. Other categories (API, REG, DIR, FILES_EXT,
    STR, DROP) aren't used by compute_features() and are skipped.
    """
    column_map: dict[int, tuple[EventType, str]] = {}
    with open(variable_names_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or ";" not in line:
                continue
            idx_str, _, rest = line.partition(";")
            if not rest.startswith("FILES:"):
                continue
            parts = rest.split(":", 2)
            if len(parts) != 3:
                continue
            _, subtype, path = parts
            event_type = _CATEGORY_TO_EVENT_TYPE.get(subtype)
            if event_type is None:  # e.g. FILES:READ -- not tracked
                continue
            # VariableNames.txt indices are 1-based and align with CSV
            # column position (1-based); convert to 0-based for pandas.
            column_map[int(idx_str) - 1] = (event_type, path)
    return column_map


def build_dataset(
    csv_path: str,
    variable_names_path: str,
    common_extensions: list[str],
    max_rows: int | None = None,
) -> pd.DataFrame:
    """Build the labeled feature DataFrame from the Sgandurra et al.
    dataset, in the same schema as mlran_parser/dsti_parser's
    build_dataset() output (sample_id, 3 features, label).
    """
    column_map = load_files_column_map(variable_names_path)
    files_columns = sorted(column_map.keys())

    # Only read the columns we actually need (ID=0, Label=1, plus every
    # FILES:* column) -- keeps this fast and memory-light despite the
    # dataset having ~31k columns total.
    usecols = [0, 1] + files_columns
    df_raw = pd.read_csv(
        csv_path,
        header=None,
        usecols=usecols,
        dtype="int32",
        nrows=max_rows,
    )

    rows = []
    for _, row in df_raw.iterrows():
        sample_id = int(row[0])
        label = int(row[1])
        events = []
        for col_idx in files_columns:
            if row[col_idx] == 1:
                event_type, path = column_map[col_idx]
                events.append(FileEvent(path=path, event_type=event_type))
        fv = compute_features(events, common_extensions)
        rows.append({"sample_id": sample_id, **fv.as_dict(), "label": label})

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
        csv_path="data/raw/sgandurra2016/RansomwareData.csv",
        variable_names_path="data/raw/sgandurra2016/VariableNames.txt",
        common_extensions=cfg["features"]["common_extensions"],
    )
    out_path = "data/processed/features_sgandurra2016.csv"
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows to {out_path}")
    print(df["label"].value_counts())
