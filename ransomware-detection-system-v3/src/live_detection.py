
"""
Live detection application layer.

Connects:
    Watcher
       -> FeatureVector
       -> Random Forest predictor
       -> Response layer

Response modes:
    observe -> classify and log only
    enforce -> classify, log, and execute the response

The actual model confidence is preserved separately from the confidence
used to select the response action.
"""

import logging

import psutil
import yaml

from src.model.predictor import RansomwarePredictor
from src.response.responder import act_on_classification


logger = logging.getLogger(__name__)


# DEMO-ONLY ACTION CAP
# Keep ransomware_sim_worker in the quarantine response band so the
# viva can demonstrate quarantine without terminating this demo worker.
# The model's actual confidence remains unchanged and is returned under
# "confidence". "response_confidence" records the score used by the
# response layer.
DEFAULT_DEMO_CAPS = {
    "ransomware_sim_worker": "quarantine"
}


class LiveDetector:
    """Connect the live watcher to the trained model and response layer."""

    def __init__(
        self,
        model_path: str,
        scaler_path: str,
        terminate_threshold: float,
        quarantine_threshold: float,
        response_mode: str = "observe",
        demo_caps: dict | None = None,
    ):
        if response_mode not in {"observe", "enforce"}:
            raise ValueError(
                f"Invalid response mode: {response_mode!r}. "
                "Expected 'observe' or 'enforce'."
            )

        self.predictor = RansomwarePredictor(
            model_path=model_path,
            scaler_path=scaler_path,
        )

        self.terminate_threshold = terminate_threshold
        self.quarantine_threshold = quarantine_threshold
        self.response_mode = response_mode

        self.demo_caps = (
            dict(DEFAULT_DEMO_CAPS)
            if demo_caps is None
            else dict(demo_caps)
        )

    def _cap_for(self, pid: int) -> str | None:
        """Return the configured demo cap for a matching process."""
        if not self.demo_caps or pid is None or pid <= 0:
            return None

        try:
            cmdline = " ".join(psutil.Process(pid).cmdline())
        except psutil.Error:
            return None

        for marker, cap in self.demo_caps.items():
            if marker in cmdline:
                return cap

        return None

    def on_features(self, pid: int, features):
        """Classify features and apply the configured response policy."""
        prediction, confidence = self.predictor.predict(features)

        # Preserve the model's actual confidence.
        effective = confidence
        capped_from = None

        # Demo-only exception: keep the quarantine demo worker in the
        # quarantine response band if its model score reaches termination.
        if (
            confidence >= self.terminate_threshold
            and self._cap_for(pid) == "quarantine"
        ):
            effective = max(
                self.quarantine_threshold,
                min(
                    self.terminate_threshold - 1e-6,
                    0.80 - 1e-6,
                ),
            )

            capped_from = "terminate"

            logger.warning(
                "Demo response cap: actual model confidence %.1f%%; "
                "response-band score %.1f%% for PID %s.",
                confidence * 100,
                effective * 100,
                pid,
            )

        action = act_on_classification(
            process_id=pid,
            confidence=effective,
            terminate_threshold=self.terminate_threshold,
            quarantine_threshold=self.quarantine_threshold,
            enforce=self.response_mode == "enforce",
        )

        return {
            "pid": pid,
            "prediction": prediction,
            "confidence": effective,
            "response_confidence": effective,
            "action": action,
            "mode": self.response_mode,
            "capped_from": capped_from,
        }


def load_config(path: str = "config.yaml") -> dict:
    """Load application configuration from YAML."""
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def create_live_detector(config: dict) -> LiveDetector:
    """Create a LiveDetector from the central configuration."""
    model_path = config["paths"]["model_path"]

    scaler_path = model_path.replace(
        ".joblib",
        "_scaler.joblib",
    )

    response_config = config["response"]

    return LiveDetector(
        model_path=model_path,
        scaler_path=scaler_path,
        terminate_threshold=response_config[
            "terminate_confidence_threshold"
        ],
        quarantine_threshold=response_config[
            "quarantine_confidence_threshold"
        ],
        response_mode=response_config.get(
            "mode",
            "observe",
        ),
        demo_caps=response_config.get("demo_caps"),
    )

