"""
Feature-vector-level augmentation for the training split (Step 3).

Uses SMOTE (Synthetic Minority Oversampling Technique) or ADASYN
(Adaptive Synthetic Sampling) to generate new synthetic feature vectors
by interpolating between existing REAL minority-class (goodware) samples
in the training split. Both are standard, well-established techniques
for small/imbalanced tabular datasets.

WHY NOT A GAN (CTGAN etc.): GAN-based tabular synthesis needs hundreds to
thousands of real examples to learn a meaningful data distribution; with
roughly 5 real goodware samples in the training split, a GAN would just
memorize noise rather than learn anything generalizable. SMOTE/ADASYN
are appropriate here specifically because they interpolate between real
neighbors rather than learning a distribution from scratch, which works
even at this small a scale.

SCOPE BOUNDARY, stated plainly (same principle as any augmentation
approach): synthetic rows are added ONLY to the training split. The
held-out test split is always the real, unaugmented data only --
otherwise evaluation metrics would partly measure fit to the augmenter
rather than real detection performance.

SMALL-SAMPLE CAVEAT: SMOTE/ADASYN's k_neighbors parameter must be
strictly less than the minority class's sample count in the training
split (here, ~5 goodware samples), so k_neighbors is capped
automatically rather than left at library defaults (which assume
k_neighbors=5 and would raise an error on a class this small).
"""

import numpy as np
import pandas as pd

from src.utils.logger import get_logger

logger = get_logger("augmentation")

FEATURE_COLUMNS = ["modification_frequency", "extension_change_rate", "file_access_breadth"]


def augment_training_set(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    method: str = "smote",
    k_neighbors: int = 3,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.Series]:
    """Return (X_train_augmented, y_train_augmented) with synthetic
    minority-class rows added. Real rows are always included unchanged;
    synthetic rows are appended, rounded to non-negative integers to
    match the real features' count-based semantics.

    method: "smote" or "adasyn". "none" returns the input unchanged.
    """
    if method == "none":
        return X_train, y_train

    class_counts = y_train.value_counts()
    minority_count = class_counts.min()
    # k_neighbors must be < minority_count, or the library raises.
    safe_k = min(k_neighbors, minority_count - 1)
    if safe_k < 1:
        logger.warning(
            "Minority class has only %d sample(s) in the training split -- "
            "too few for SMOTE/ADASYN (need >=2). Returning unaugmented data.",
            minority_count,
        )
        return X_train, y_train

    if method == "smote":
        from imblearn.over_sampling import SMOTE
        sampler = SMOTE(k_neighbors=safe_k, random_state=random_state)
    elif method == "adasyn":
        from imblearn.over_sampling import ADASYN
        sampler = ADASYN(n_neighbors=safe_k, random_state=random_state)
    else:
        raise ValueError(f"Unknown augmentation method: {method!r}")

    X_res, y_res = sampler.fit_resample(X_train, y_train)

    # Round back to non-negative integers -- SMOTE/ADASYN interpolate in
    # continuous space, but these three features are real event counts.
    X_res = pd.DataFrame(X_res, columns=FEATURE_COLUMNS)
    X_res[FEATURE_COLUMNS] = X_res[FEATURE_COLUMNS].round().clip(lower=0).astype(int)
    y_res = pd.Series(y_res, name=y_train.name)

    n_synthetic = len(X_res) - len(X_train)
    logger.info(
        "%s augmentation (k=%d): added %d synthetic row(s); class balance now %s",
        method.upper(), safe_k, n_synthetic, y_res.value_counts().to_dict(),
    )

    return X_res, y_res
