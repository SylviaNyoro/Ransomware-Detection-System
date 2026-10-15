from pathlib import Path

from src.feature_engineering.mlran_parser import build_dataset, extract_events_from_report

RAW_DIR = Path("data/raw/mlran")
COMMON_EXT = [".txt", ".docx", ".xlsx", ".pdf", ".csv", ".png", ".jpg", ".py", ".json", ".log"]


def test_extract_events_from_real_report():
    """10027.json is one of the richer bundled MLRan examples."""
    events = extract_events_from_report(str(RAW_DIR / "json_reports" / "10027.json"))
    assert len(events) > 0
    # file_created + file_written + file_opened all present in this sample
    event_types = {e.event_type for e in events}
    assert len(event_types) >= 2


def test_build_dataset_from_bundled_samples():
    df = build_dataset(
        raw_reports_dir=str(RAW_DIR / "json_reports"),
        metadata_csv=str(RAW_DIR / "mlran_dataset_metadata.csv"),
        common_extensions=COMMON_EXT,
    )
    # The 20 bundled example reports are all labeled ransomware (label=1);
    # no goodware examples ship publicly yet (see module docstring).
    assert len(df) == 20
    assert set(df["label"].unique()) == {1}
    assert {
        "modification_frequency",
        "extension_change_rate",
        "file_access_breadth",
    }.issubset(df.columns)
