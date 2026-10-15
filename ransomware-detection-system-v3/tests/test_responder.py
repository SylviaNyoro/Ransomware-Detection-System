from unittest.mock import patch
from src.response.responder import act_on_classification

TERMINATE_THRESHOLD = 0.95
QUARANTINE_THRESHOLD = 0.50

def test_49_percent_continues():
    assert act_on_classification(None, 0.49, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD) == "continue"

def test_50_percent_quarantines():
    assert act_on_classification(None, 0.50, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD) == "quarantine"

def test_94_percent_quarantines():
    assert act_on_classification(None, 0.94, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD) == "quarantine"

def test_95_percent_terminates():
    assert act_on_classification(None, 0.95, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD) == "terminate"

def test_observe_mode_does_not_quarantine():
    with patch("src.response.responder._quarantine_process") as mock:
        action = act_on_classification(12345, 0.60, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD, enforce=False)
    assert action == "quarantine"
    mock.assert_not_called()

def test_observe_mode_does_not_terminate():
    with patch("src.response.responder._terminate_process") as mock:
        action = act_on_classification(12345, 0.96, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD, enforce=False)
    assert action == "terminate"
    mock.assert_not_called()

def test_enforce_mode_calls_quarantine():
    with patch("src.response.responder._quarantine_process") as mock:
        action = act_on_classification(12345, 0.60, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD, enforce=True)
    assert action == "quarantine"
    mock.assert_called_once_with(12345)

def test_enforce_mode_calls_terminate():
    with patch("src.response.responder._terminate_process") as mock:
        action = act_on_classification(12345, 0.96, TERMINATE_THRESHOLD, QUARANTINE_THRESHOLD, enforce=True)
    assert action == "terminate"
    mock.assert_called_once_with(12345)
