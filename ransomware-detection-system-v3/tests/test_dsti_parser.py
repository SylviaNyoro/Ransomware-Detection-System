from pathlib import Path

from src.feature_engineering.dsti_parser import build_dataset

SAMPLES_DIR = Path("data/raw/dsti/preprocessed-json-samples")
COMMON_EXT = [".txt", ".docx", ".xlsx", ".pdf", ".csv", ".png", ".jpg", ".py", ".json", ".log"]


def test_build_dataset_from_dsti_samples():
    df = build_dataset(str(SAMPLES_DIR), COMMON_EXT)
    assert len(df) == 12
    assert set(df["label"].unique()) == {0, 1}
    # balanced in this bundled example set
    assert (df["label"] == 0).sum() == 6
    assert (df["label"] == 1).sum() == 6
