"""
Combines MLRan and DSTI into the training corpus (Ch. 3.6).

Sgandurra 2016 goodware was evaluated and excluded: its goodware samples
are Windows XP-era software installers with high modification_frequency
(up to 109) and file_access_breadth (up to 30), which overlap with the
ransomware signal in the 3-feature space and caused the classifier to
misidentify real ransomware activity as goodware. This is documented as
a limitation in Ch. 5 (see false-positive analysis).
"""

import pandas as pd
import yaml

from src.feature_engineering import dsti_parser, mlran_parser


def build_combined_dataset(config_path: str = "config.yaml") -> pd.DataFrame:
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    common_ext = cfg["features"]["common_extensions"]

    mlran_df = mlran_parser.build_dataset(
        raw_reports_dir=f"{cfg['paths']['raw_mlran_dir']}/json_reports",
        metadata_csv=f"{cfg['paths']['raw_mlran_dir']}/mlran_dataset_metadata.csv",
        common_extensions=common_ext,
    )
    mlran_df["source"] = "mlran"

    dsti_df = dsti_parser.build_dataset(
        samples_dir="data/raw/dsti/preprocessed-json-samples",
        common_extensions=common_ext,
    )
    dsti_df["source"] = "dsti"

    combined = pd.concat([mlran_df, dsti_df], ignore_index=True)
    return combined


if __name__ == "__main__":
    df = build_combined_dataset()
    out_path = "data/processed/features_combined.csv"
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows to {out_path}")
    print(df.groupby(["source", "label"]).size())
