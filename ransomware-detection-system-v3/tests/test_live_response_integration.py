"""Integration tests for live detection and response reporting."""

from unittest.mock import patch

import pytest

from src.live_detection import LiveDetector
from src.response.enforcement_controller import EnforcementController


@pytest.mark.parametrize(
    "confidence,outcome,action",
    [
        (0.10, "Benign", "continue"),
        (0.50, "Uncertain", "quarantine"),
        (0.95, "Ransomware", "terminate"),
    ],
)
def test_observe_mode_reports_classification(confidence, outcome, action):
    with patch("src.live_detection.RansomwarePredictor") as predictor:
        predictor.return_value.predict.return_value = (0, confidence)
        predictor.return_value.threshold = 0.625

        detector = LiveDetector(
            model_path="unused.joblib",
            response_mode="observe",
        )

        result = detector.on_features(-1, {})

    assert result["outcome"] == outcome
    assert result["action"] == action
    assert result["mode"] == "observe"
    assert result["response_executed"] is False


@pytest.mark.parametrize("confidence", [0.50, 0.95])
def test_unauthorized_process_cannot_be_controlled(confidence):
    controller = EnforcementController()

    with (
        patch(
            "src.response.enforcement_controller.is_authorized_demo",
            return_value=False,
        ),
        patch(
            "src.response.enforcement_controller.execute_demo_action"
        ) as executor,
    ):
        result = controller.evaluate(
            pid=12345,
            confidence=confidence,
            mode="enforce",
        )

    assert result["authorized"] is False
    assert result["response_executed"] is False
    assert result["status"] == "unauthorized_process"
    executor.assert_not_called()


def test_enforce_mode_reports_controller_result():
    with (
        patch("src.live_detection.RansomwarePredictor") as predictor,
        patch(
            "src.live_detection.EnforcementController"
        ) as controller,
    ):
        predictor.return_value.predict.return_value = (1, 0.95)
        predictor.return_value.threshold = 0.625

        controller.return_value.evaluate.return_value = {
            "action": "terminate",
            "mode": "enforce",
            "authorized": True,
            "response_executed": True,
            "status": "terminated_verified",
        }

        detector = LiveDetector(
            model_path="unused.joblib",
            response_mode="enforce",
        )

        result = detector.on_features(12345, {})

    assert result["mode"] == "enforce"
    assert result["response_executed"] is True
    assert result["authorized"] is True
    assert result["enforcement_status"] == "terminated_verified"
