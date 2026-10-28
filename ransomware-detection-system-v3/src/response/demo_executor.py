"""Verified process control for explicitly authorized demonstrations only."""

import os
import time

import psutil

from src.response.demo_authorization import is_authorized_demo


def execute_demo_action(pid: int, action: str) -> dict:
    """Execute and verify one action against an authorized demo process."""
    result = {
        "pid": pid,
        "action": action,
        "response_executed": False,
        "status": "not_executed",
    }

    if action not in {"continue", "quarantine", "terminate"}:
        result["status"] = "invalid_action"
        return result

    if action == "continue":
        result["status"] = "continue"
        return result

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        result["status"] = "invalid_pid"
        return result

    try:
        protected = {os.getpid(), 1}
        protected.update(p.pid for p in psutil.Process().parents())

        if pid in protected:
            result["status"] = "protected_process"
            return result

        if not is_authorized_demo(pid):
            result["status"] = "unauthorized_process"
            return result

        process = psutil.Process(pid)

        if action == "quarantine":
            if process.status() == psutil.STATUS_STOPPED:
                result["status"] = "already_suspended"
                return result

            process.suspend()
            time.sleep(0.1)

            if process.status() == psutil.STATUS_STOPPED:
                result["response_executed"] = True
                result["status"] = "suspended_verified"

        elif action == "terminate":
            process.terminate()

            try:
                process.wait(timeout=2)
            except psutil.TimeoutExpired:
                result["status"] = "termination_not_confirmed"
                return result

            result["response_executed"] = True
            result["status"] = "terminated_verified"

    except (psutil.Error, OSError, ValueError) as exc:
        result["status"] = f"execution_error:{type(exc).__name__}"

    return result
