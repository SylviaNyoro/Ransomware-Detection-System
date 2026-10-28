"""Controlled enforcement for authorized demonstration processes."""

import psutil

from src.response.demo_authorization import is_authorized_demo
from src.response.demo_executor import execute_demo_action


class EnforcementController:
    """Evaluate confidence scores and safely execute demo responses."""

    def __init__(
        self,
        quarantine_threshold=0.20,
        terminate_threshold=0.625,
    ):
        if not 0 <= quarantine_threshold < terminate_threshold <= 1:
            raise ValueError("Invalid enforcement thresholds.")

        self.quarantine_threshold = quarantine_threshold
        self.terminate_threshold = terminate_threshold
        self.handled = set()

    def evaluate(self, pid, confidence, mode="observe"):
        if not 0 <= confidence <= 1:
            raise ValueError("Invalid confidence score.")

        if mode not in {"observe", "enforce"}:
            raise ValueError("Invalid response mode.")

        if confidence < self.quarantine_threshold:
            action = "continue"
        elif confidence < self.terminate_threshold:
            action = "quarantine"
        else:
            action = "terminate"

        authorized = is_authorized_demo(pid)

        result = {
            "pid": pid,
            "action": action,
            "mode": mode,
            "authorized": authorized,
            "response_executed": False,
            "status": "continue" if action == "continue" else "observed",
        }

        if mode == "observe" or action == "continue":
            return result

        if not authorized:
            result["status"] = "unauthorized_process"
            return result

        try:
            process = psutil.Process(pid)
            identity = (pid, process.create_time())
        except (psutil.Error, TypeError, ValueError):
            result["status"] = "process_unavailable"
            return result

        if identity in self.handled:
            result["status"] = "already_handled"
            return result

        execution = execute_demo_action(pid, action)

        result["response_executed"] = execution["response_executed"]
        result["status"] = execution["status"]

        if execution["response_executed"]:
            self.handled.add(identity)

        return result
