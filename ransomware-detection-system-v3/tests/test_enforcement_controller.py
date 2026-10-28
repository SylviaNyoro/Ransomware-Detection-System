"""Safety tests for controlled enforcement decisions."""

from unittest.mock import patch

import pytest

from src.response.enforcement_controller import EnforcementController


@pytest.mark.parametrize(
    "confidence,expected",
    [
        (0.1033, "continue"),
        (0.5095, "quarantine"),
        (0.9564, "terminate"),
    ],
)
def test_response_decisions(confidence, expected):
    controller = EnforcementController()

    result = controller.evaluate(
        pid=12345,
        confidence=confidence,
        mode="observe",
    )

    assert result["action"] == expected
    assert result["response_executed"] is False


def test_unauthorized_process():
    controller = EnforcementController()

    with patch(
        "src.response.enforcement_controller.is_authorized_demo",
        return_value=False,
    ):
        result = controller.evaluate(
            pid=12345,
            confidence=0.9564,
            mode="enforce",
        )

    assert result["authorized"] is False
    assert result["response_executed"] is False
    assert result["status"] == "unauthorized_process"


def test_repeated_evaluation_does_not_execute():
    controller = EnforcementController()

    with patch(
        "src.response.enforcement_controller.is_authorized_demo",
        return_value=True,
    ):
        first = controller.evaluate(12345, 0.9564, "enforce")
        second = controller.evaluate(12345, 0.9564, "enforce")

    assert first["response_executed"] is False
    assert second["response_executed"] is False


def test_invalid_confidence_rejected():
    controller = EnforcementController()

    with pytest.raises(ValueError):
        controller.evaluate(12345, 1.5)
