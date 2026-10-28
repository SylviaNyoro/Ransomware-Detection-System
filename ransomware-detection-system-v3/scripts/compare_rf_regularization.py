"""Compare Random Forest regularization using the existing grouped split."""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score

DATASET = "data/processed/rands_filesystem_features_50000.csv"
MANIFEST = "results/rands_grouped/split_manifest.csv"

FEATURES = [
    "changed_file_count",
    "file_access_breadth",
    "directory_traversal_breadth",
    "file_creation_count",
    "file_deletion_count",
    "extension_diversity",
    "file_activity_total",
]

CONFIGURATIONS = [
    (15, 2),   # Existing configuration
    (12, 2),
    (10, 2),
    (12, 5),
    (10, 5),
    (10, 10),
]

df = pd.read_csv(DATASET)
manifest = pd.read_csv(MANIFEST)

merged = df.merge(
    manifest[["sha256", "split"]],
    on="sha256",
    validate="one_to_one",
)

train = merged[merged["split"] == "train"]
val = merged[merged["split"] == "validation"]

X_train = train[FEATURES]
y_train = train["label"]

X_val = val[FEATURES]
y_val = val["label"]

results = []

for depth, leaf in CONFIGURATIONS:
    print(f"Training max_depth={depth}, min_samples_leaf={leaf}...", flush=True)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=depth,
        min_samples_leaf=leaf,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    positive_index = list(model.classes_).index(1)

    train_probs = model.predict_proba(X_train)[:, positive_index]
    val_probs = model.predict_proba(X_val)[:, positive_index]

    candidates = []

    for threshold in np.round(np.arange(0.50, 0.951, 0.025), 3):
        predictions = (val_probs >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            y_val, predictions, labels=[0, 1]
        ).ravel()

        recall = tp / (tp + fn)
        fpr = fp / (fp + tn)

        if recall >= 0.85:
            candidates.append({
                "threshold": threshold,
                "recall": recall,
                "fpr": fpr,
                "f1": f1_score(y_val, predictions),
                "fp": fp,
                "fn": fn,
            })

    if not candidates:
        print("  No threshold achieved 85% recall.")
        continue

    best = sorted(
        candidates,
        key=lambda row: (row["fpr"], -row["f1"])
    )[0]

    train_predictions = (
        train_probs >= best["threshold"]
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_train, train_predictions, labels=[0, 1]
    ).ravel()

    results.append({
        "depth": depth,
        "leaf": leaf,
        "threshold": best["threshold"],
        "train_fpr": fp / (fp + tn),
        "val_fpr": best["fpr"],
        "val_recall": best["recall"],
        "val_f1": best["f1"],
        "val_fp": best["fp"],
        "val_fn": best["fn"],
    })

print("\n=== REGULARIZATION COMPARISON ===")

if results:
    table = pd.DataFrame(results).sort_values(
        ["val_fpr", "val_f1"],
        ascending=[True, False],
    )

    print(table.round(4).to_string(index=False))
else:
    print("No configuration met the minimum recall requirement.")

print("\nNo datasets or saved models modified.")
