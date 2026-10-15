"""
Classifier evaluation (proposal Ch. 3.7, Testing).

Computes the six classifier-level metrics named in the proposal:
    Detection Accuracy, Precision, Recall, F1 Score,
    False Positive Rate, False Negative Rate

on a held-out test split. Operational metrics (reaction time, files
encrypted before containment, CPU/memory overhead) are NOT computed here
-- those require the live pipeline (Step 4/5) and are measured separately
during the small-scale demonstration, per Ch. 3.7.

CAVEAT (repeated from train.py -- important enough to repeat): with a
32-sample dataset and a stratified 80/20 split, the held-out test set
here has on the order of 6-7 samples. Metrics computed on that few
samples have very wide confidence intervals and can swing enormously
from one random_state to the next. Report these as illustrative of the
pipeline working correctly, not as a precise, generalizable accuracy
figure.
"""

"""
Evaluate the Random Forest ransomware detector.

Reports classification metrics and a confusion matrix.
The held-out test set is small, so results are illustrative.
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def evaluate(model, X_test, y_test) -> dict:
    """Calculate binary classification metrics."""
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(
        y_test, y_pred, labels=[0, 1]
    ).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "test_set_size": len(y_test),
    }


def main():
    # Recreate the same deterministic split and preprocessing
    # used by train.py, then evaluate without retraining artifacts.
    from src.model.train import load_config, train

    config = load_config()
    model, scaler, X_test, y_test = train(config)

    y_pred = model.predict(X_test)

    print("\n=== CLASSIFICATION REPORT ===")
    print(
        classification_report(
            y_test,
            y_pred,
            labels=[0, 1],
            target_names=["Goodware", "Ransomware"],
            zero_division=0,
        )
    )

    print("=== CONFUSION MATRIX ===")
    print("Rows = actual; columns = predicted")
    print("                 Predicted Goodware  Predicted Ransomware")
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(f"Actual Goodware          {cm[0, 0]:<15} {cm[0, 1]}")
    print(f"Actual Ransomware        {cm[1, 0]:<15} {cm[1, 1]}")

    print("\n=== SUMMARY METRICS ===")
    metrics = evaluate(model, X_test, y_test)
    for name, value in metrics.items():
        print(f"{name}: {value}")

    print(
        "\nNOTE: This is a small held-out test set. "
        "Treat these results as proof-of-concept, not "
        "as a reliable estimate of real-world performance."
    )


if __name__ == "__main__":
    main()
