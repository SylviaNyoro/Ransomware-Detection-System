"""Inference wrapper for the trained Random Forest ransomware model."""

from __future__ import annotations

import joblib
import pandas as pd

from src.model.train import FEATURE_COLUMNS


class RansomwarePredictor:
    """Load the persisted model/scaler and classify FeatureVector objects."""

    def __init__(self, model_path: str, scaler_path: str):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

    def _to_row(self, features) -> pd.DataFrame:
        if hasattr(features, "as_dict"):
            data = features.as_dict()
        elif isinstance(features, dict):
            data = features
        else:
            raise TypeError(
                "features must be a FeatureVector or dictionary"
            )

        return pd.DataFrame([data])[FEATURE_COLUMNS]

    def predict(self, features) -> tuple[int, float]:
        """Return (prediction, malicious-class confidence)."""
        row = self._to_row(features)
        scaled = self.scaler.transform(row)
        prediction = int(self.model.predict(scaled)[0])
        probabilities = self.model.predict_proba(scaled)[0]

        # Class 1 is the ransomware/malicious class.
        classes = list(self.model.classes_)
        if 1 in classes:
            confidence = float(probabilities[classes.index(1)])
        else:
            confidence = float(probabilities[0]) if prediction == 1 else 0.0

        return prediction, confidence
