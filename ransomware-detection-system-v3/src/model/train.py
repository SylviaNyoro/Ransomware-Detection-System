"""
Random Forest training script (proposal Ch. 3.6-3.7, final approach:
Track 1 only -- MLRan raw ransomware logs + DSTI raw goodware logs).

Pipeline, matching Ch. 3.6's final paragraph:
  1. Load the labeled feature dataset (build_combined_dataset.py: MLRan + DSTI).
  2. Preprocess: drop duplicates, normalize the three features.
     (Random Forest's decision boundaries are scale-invariant, so
     normalization doesn't change what the model learns -- it's included
     to match the documented preprocessing methodology in Ch. 3.6, and
     the fitted scaler is persisted alongside the model so live inference
     can apply the identical transform, keeping train/deployment data
     consistent as Ch. 3.6's final paragraph requires.)
  3. Stratified train/test split (config.yaml -> model.test_size).
  4. Augment the TRAINING split only via SMOTE/ADASYN
     (config.yaml -> augmentation; see src/model/augmentation.py for the
     full rationale, including why a GAN-based approach was rejected as
     unsuitable at this sample size).
  5. Train a RandomForestClassifier (config.yaml -> model hyperparameters).
  6. Print feature importances to confirm all three features contribute
     (Ch. 3.6, "Not all MLRan's recorded event types...").
  7. Persist the trained model and scaler to models/.
  8. Hand off (X_test, y_test, model) to evaluate.py for Ch. 3.7 metrics.

IMPORTANT, stated plainly rather than glossed over: the real, correctly
labeled data behind this is only 32 samples (26 ransomware / 6 goodware,
22 after deduplication). SMOTE/ADASYN augmentation (see
src/model/augmentation.py) helps the training split better represent
the minority class, but it does not manufacture new real evidence --
synthetic rows are interpolations between real neighbors, not new
independent observations. The held-out test split is always real,
unaugmented data only. Treat every metric this produces as a
proof-of-concept result, per Ch. 3.6's explicit acknowledged-limitation
paragraph, not as evidence of real-world detection performance.
"""

import joblib
import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.feature_engineering.build_combined_dataset import build_combined_dataset
from src.model.augmentation import augment_training_set
from src.utils.logger import get_logger

FEATURE_COLUMNS = ["modification_frequency", "extension_change_rate", "file_access_breadth"]

logger = get_logger("train")


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_and_preprocess() -> pd.DataFrame:
    """Build the combined MLRan+DSTI dataset and drop duplicate rows.
    (Normalization is applied later, fit only on the training split, to
    avoid leaking test-set statistics into training -- see train().)
    """
    df = build_combined_dataset()
    before = len(df)
    df = df.drop_duplicates(subset=FEATURE_COLUMNS + ["label"]).reset_index(drop=True)
    dropped = before - len(df)
    if dropped:
        logger.info("Dropped %d duplicate row(s)", dropped)
    return df


def train(config: dict, df: pd.DataFrame | None = None):
    """Train, evaluate-ready-split, and persist the Random Forest classifier.

    Returns (model, scaler, X_test_scaled, y_test) so callers (this
    script, evaluate.py, or tests) can evaluate without re-training.
    """
    if df is None:
        df = load_and_preprocess()

    if len(df) < 10 or df["label"].nunique() < 2:
        raise ValueError(
            f"Dataset too small or not both classes present to train meaningfully "
            f"(got {len(df)} rows, {df['label'].nunique()} class(es)). "
            f"See Ch. 3.6's acknowledged data-scale limitation."
        )

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    model_cfg = config["model"]
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=model_cfg["test_size"],
        random_state=model_cfg["random_state"],
        stratify=y,  # preserve the 26/6 class ratio in both splits
    )
    logger.info(
        "Split: %d train (%d ransomware / %d goodware), %d test (%d ransomware / %d goodware)",
        len(X_train), (y_train == 1).sum(), (y_train == 0).sum(),
        len(X_test), (y_test == 1).sum(), (y_test == 0).sum(),
    )

    aug_cfg = config.get("augmentation", {"enabled": False})
    if aug_cfg.get("enabled", False):
        X_train, y_train = augment_training_set(
            X_train,
            y_train,
            method=aug_cfg.get("method", "smote"),
            k_neighbors=aug_cfg.get("k_neighbors", 3),
            random_state=model_cfg["random_state"],
        )
        logger.info(
            "After augmentation: %d train (%d ransomware / %d goodware) -- test split unchanged",
            len(X_train), (y_train == 1).sum(), (y_train == 0).sum(),
        )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=model_cfg["n_estimators"],
        max_depth=model_cfg["max_depth"],
        random_state=model_cfg["random_state"],
    )
    model.fit(X_train_scaled, y_train)

    importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
    logger.info("Feature importances: %s", importances)
    for name, score in sorted(importances.items(), key=lambda kv: -kv[1]):
        logger.info("  %-25s %.3f", name, score)

    return model, scaler, X_test_scaled, y_test


def save_artifacts(model, scaler, config: dict):
    model_path = config["paths"]["model_path"]
    scaler_path = model_path.replace(".joblib", "_scaler.joblib")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    logger.info("Saved model to %s", model_path)
    logger.info("Saved scaler to %s", scaler_path)


if __name__ == "__main__":
    cfg = load_config()
    trained_model, fitted_scaler, X_test, y_test = train(cfg)
    save_artifacts(trained_model, fitted_scaler, cfg)

    from src.model.evaluate import evaluate

    metrics = evaluate(trained_model, X_test, y_test)
    print("\n--- Held-out test metrics (n=%d; see module docstring caveat) ---" % len(y_test))
    for name, value in metrics.items():
        print(f"{name}: {value}")
