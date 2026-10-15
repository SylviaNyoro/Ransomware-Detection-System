from src.feature_engineering.build_combined_dataset import build_combined_dataset


def test_build_combined_dataset():
    df = build_combined_dataset()
    assert len(df) == 32
    assert set(df["source"].unique()) == {"mlran", "dsti"}
    assert (df["label"] == 0).sum() == 6  # all from dsti (goodware)
    assert (df["label"] == 1).sum() == 26  # 20 mlran + 6 dsti
