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



def generate_synthetic_samples(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    target_size: int = 200,
    random_state: int = 42,
    allow_resampling: bool = False,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Generate a balanced augmented training dataset.

    Uses within-class interpolation and limited extrapolation.
    All original training samples are retained.

    Never call before splitting the original dataset.
    """
    if target_size < len(X_train):
        raise ValueError("Target smaller than original training set.")

    X_original = X_train[FEATURE_COLUMNS].reset_index(drop=True).copy()
    y_original = pd.Series(y_train).reset_index(drop=True).copy()

    rng = np.random.default_rng(random_state)

    classes = sorted(y_original.unique())

    if len(classes) != 2:
        raise ValueError("Exactly two classes required.")

    goals = {
        classes[0]: target_size // 2,
        classes[1]: target_size - target_size // 2,
    }

    synthetic_rows = []
    synthetic_labels = []

    seen = {
        tuple(row) + (label,)
        for row, label in zip(
            X_original.to_numpy(),
            y_original.to_numpy(),
        )
    }

    for label in classes:
        values = X_original.loc[
            y_original == label
        ].to_numpy(dtype=float)

        required = goals[label] - len(values)

        if required < 0:
            raise ValueError("Class exceeds target allocation.")

        if required > 0 and len(values) < 2:
            raise ValueError(
                f"Class {label} has insufficient originals."
            )

        feature_min = values.min(axis=0)
        feature_max = values.max(axis=0)
        spread = np.maximum(
            values.std(axis=0), 1.0
        )

        generated = 0

        # Progressively explore a wider neighborhood.
        for expansion in (0.0, 0.25, 0.5, 1.0):
            if generated >= required:
                break

            lower = np.maximum(
                0,
                feature_min - expansion * spread,
            )

            upper = (
                feature_max + expansion * spread
            )

            for _ in range(30000):
                if generated >= required:
                    break

                i, j = rng.choice(
                    len(values),
                    size=2,
                    replace=False,
                )

                alpha = rng.uniform(-0.2, 1.2)

                candidate = (
                    alpha * values[i] +
                    (1 - alpha) * values[j]
                )

                noise = rng.normal(
                    0,
                    0.25 * spread,
                    size=len(FEATURE_COLUMNS),
                )

                candidate = np.rint(
                    np.clip(
                        candidate + noise,
                        lower,
                        upper,
                    )
                ).astype(int)

                key = tuple(candidate) + (label,)

                if key in seen:
                    continue

                seen.add(key)
                synthetic_rows.append(candidate.tolist())
                synthetic_labels.append(label)
                generated += 1

        if generated != required:
            if not allow_resampling:
                raise RuntimeError(
                    f"Class {label}: generated {generated}/"
                    f"{required} unique synthetic samples. "
                    "Insufficient plausible feature diversity."
                )

            remaining = required - generated

            # Resample from original training observations only.
            # These are repeated rows, not new independent samples.
            indices = rng.choice(
                len(values),
                size=remaining,
                replace=True,
            )

            for idx in indices:
                synthetic_rows.append(
                    values[idx].astype(int).tolist()
                )
                synthetic_labels.append(label)

            logger.warning(
                "Class %s: %d unique synthetic observations "
                "and %d resampled original observations",
                label,
                generated,
                remaining,
            )

    X_generated = pd.DataFrame(
        synthetic_rows,
        columns=FEATURE_COLUMNS,
    )

    y_generated = pd.Series(
        synthetic_labels,
        name=y_original.name,
    )

    X_augmented = pd.concat(
        [X_original, X_generated],
        ignore_index=True,
    )

    y_augmented = pd.concat(
        [y_original, y_generated],
        ignore_index=True,
    )

    if len(X_augmented) != target_size:
        raise AssertionError("Incorrect dataset size.")

    logger.info(
        "Synthetic augmentation: %d original + "
        "%d synthetic = %d",
        len(X_original),
        len(X_generated),
        len(X_augmented),
    )

    return X_augmented, y_augmented
