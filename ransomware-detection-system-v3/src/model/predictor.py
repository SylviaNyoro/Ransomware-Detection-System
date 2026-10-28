"""Random Forest inference for the seven-feature RanDS model."""

from __future__ import annotations

import joblib
import pandas as pd


class RansomwarePredictor:
    """Load the trained Random Forest bundle and classify features."""

    def __init__(self, model_path: str, scaler_path: str | None = None):
        bundle = joblib.load(model_path)

        if not isinstance(bundle, dict):
            raise ValueError(
                "Expected a RanDS model bundle containing model and features."
            )

        self.model = bundle["model"]
        self.feature_columns = list(bundle["feature_columns"])
        self.threshold = float(bundle["threshold"])

        if not 0.0 < self.threshold < 1.0:
            raise ValueError("Invalid model threshold.")

        if 1 not in self.model.classes_:
            raise ValueError("Model does not contain ransomware class 1.")

    def _to_row(self, features) -> pd.DataFrame:
        if hasattr(features, "as_dict"):
            data = features.as_dict()
        elif isinstance(features, dict):
            data = features
        else:
            raise TypeError(
                "features must be a feature vector or dictionary"
            )

        missing = [
            name
            for name in self.feature_columns
            if name not in data
        ]

        if missing:
            raise ValueError(f"Missing model features: {missing}")

        return pd.DataFrame(
            [{name: data[name] for name in self.feature_columns}],
            columns=self.feature_columns,
        )

    def predict(self, features) -> tuple[int, float]:
        """Return thresholded prediction and ransomware-class score."""
        row = self._to_row(features)

        probabilities = self.model.predict_proba(row)[0]
        class_index = list(self.model.classes_).index(1)
        confidence = float(probabilities[class_index])

        prediction = int(confidence >= self.threshold)

        return prediction, confidence

    def predict_outcome(
        self,
        features,
        lower_threshold: float = 0.20,
    ) -> tuple[str, float]:
        """Return Benign, Uncertain, or Ransomware and model score."""
        _, confidence = self.predict(features)

        if confidence < lower_threshold:
            outcome = "Benign"
        elif confidence < self.threshold:
            outcome = "Uncertain"
        else:
            outcome = "Ransomware"

        return outcome, confidence
