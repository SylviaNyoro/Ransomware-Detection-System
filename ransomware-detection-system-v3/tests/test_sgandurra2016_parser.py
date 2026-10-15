from src.feature_engineering.sgandurra2016_parser import build_dataset, load_files_column_map

CSV_PATH = "data/raw/sgandurra2016/RansomwareData.csv"
VAR_NAMES_PATH = "data/raw/sgandurra2016/VariableNames.txt"
COMMON_EXT = [".txt", ".docx", ".xlsx", ".pdf", ".csv", ".png", ".jpg", ".py", ".json", ".log"]


def test_load_files_column_map():
    col_map = load_files_column_map(VAR_NAMES_PATH)
    assert len(col_map) > 0
    # every value should be (EventType, path) with a non-empty path
    for event_type, path in list(col_map.values())[:20]:
        assert event_type is not None
        assert isinstance(path, str)


def test_build_dataset_subset_matches_known_label_distribution():
    """First 30 rows of the raw CSV are all label=1 (ransomware, IDs 100xx);
    this just proves the pipeline runs correctly end-to-end on real data."""
    df = build_dataset(CSV_PATH, VAR_NAMES_PATH, COMMON_EXT, max_rows=30)
    assert len(df) == 30
    assert set(df["label"].unique()) == {1}
    assert {
        "modification_frequency",
        "extension_change_rate",
        "file_access_breadth",
    }.issubset(df.columns)
