"""Safety requirements for live enforcement integration."""

from unittest.mock import patch

from src.response.enforcement_controller import EnforcementController


def test_observe_mode_never_executes():
    controller = EnforcementController()

    with patch(
        "src.response.enforcement_controller.is_authorized_demo",
        return_value=True,
    ):
        result = controller.evaluate(
            pid=12345,
            confidence=0.9564,
            mode="observe",
        )

    assert result["action"] == "terminate"
    assert result["response_executed"] is False


def test_unauthorized_pid_never_executes():
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
