"""
Response layer for the ransomware detection system.

Confidence bands (thresholds are read from config.yaml):

    below quarantine threshold          -> Continue monitoring
    quarantine <= confidence < terminate -> Quarantine (suspend process)
    confidence >= terminate threshold    -> Terminate (kill process)

The `enforce` flag controls whether the selected response is actually
executed. In observe mode, the system still makes and logs the decision
but does not suspend or terminate a process.

Safety rules in enforce mode:
  - A response is only executed against a valid PID (> 0). Events that
    could not be attributed to a process (pid = -1) still produce a
    decision, but there is nothing to act on.
  - The detector's own process, its ancestors (backend, dashboard,
    shell) and PID 1 are never suspended or terminated.
"""

import logging
import os
import time

import psutil


logger = logging.getLogger(__name__)


def _protected_pids() -> set[int]:
    """PIDs that must never be acted on: this process and its ancestors."""
    protected = {0, 1, os.getpid()}
    try:
        protected.update(p.pid for p in psutil.Process().parents())
    except psutil.Error:
        protected.add(os.getppid())
    return protected


def act_on_classification(
    process_id: int | None,
    confidence: float,
    terminate_threshold: float,
    quarantine_threshold: float,
    enforce: bool = True,
) -> str:
    """Select and optionally execute the response for a classified process."""
    start_time = time.perf_counter()

    if not 0.0 <= confidence <= 1.0:
        raise ValueError(
            f"Confidence must be between 0.0 and 1.0, got {confidence}"
        )

    if not 0.0 <= quarantine_threshold <= 1.0:
        raise ValueError(
            "Quarantine threshold must be between 0.0 and 1.0."
        )

    if not 0.0 <= terminate_threshold <= 1.0:
        raise ValueError(
            "Terminate threshold must be between 0.0 and 1.0."
        )

    if quarantine_threshold >= terminate_threshold:
        raise ValueError(
            "Quarantine threshold must be lower than "
            "the terminate threshold."
        )

    if confidence < quarantine_threshold:
        action = "continue"
    elif confidence < terminate_threshold:
        action = "quarantine"
    else:
        action = "terminate"

    if enforce and action != "continue":
        if process_id is None or process_id <= 0:
            logger.warning(
                "Decision '%s' made but no valid PID to act on "
                "(pid=%s): event could not be attributed to a process.",
                action,
                process_id,
            )
        elif process_id in _protected_pids():
            logger.warning(
                "Decision '%s' for PID %s skipped: protected process "
                "(detector or one of its ancestors).",
                action,
                process_id,
            )
        elif action == "quarantine":
            _quarantine_process(process_id)
        elif action == "terminate":
            _terminate_process(process_id)

    reaction_time = time.perf_counter() - start_time

    logger.info(
        "Response decision: pid=%s confidence=%.4f action=%s "
        "enforce=%s reaction_time=%.6fs",
        process_id,
        confidence,
        action,
        enforce,
        reaction_time,
    )

    return action


def _quarantine_process(process_id: int) -> None:
    """Suspend the process as the quarantine response."""
    try:
        process = psutil.Process(process_id)
        process.suspend()
    except psutil.NoSuchProcess:
        logger.warning(
            "Cannot quarantine PID %s: process no longer exists.",
            process_id,
        )
    except psutil.AccessDenied:
        logger.warning(
            "Cannot quarantine PID %s: access denied.",
            process_id,
        )


def _terminate_process(process_id: int) -> None:
    """Terminate the process as the high-confidence response."""
    try:
        process = psutil.Process(process_id)
        process.terminate()
    except psutil.NoSuchProcess:
        logger.warning(
            "Cannot terminate PID %s: process no longer exists.",
            process_id,
        )
    except psutil.AccessDenied:
        logger.warning(
            "Cannot terminate PID %s: access denied.",
            process_id,
        )
