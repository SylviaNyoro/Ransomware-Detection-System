"""
Shared helpers for the demo launchers (ransomware_sim_demo.py and
goodware_demo.py).

Each launcher runs the live monitor + classifier in its own process and
spawns a separate WORKER process (scripts/ransomware_sim_worker.py or
scripts/goodware_worker.py) that does the actual file operations. Because
the worker is a genuine, distinct OS process that holds its file handles
open, psutil's ProcessAttributor can attribute the events to its real PID
-- the same design as scripts/encryptor_worker.py.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import psutil


def spawn_worker(module: str, target: str, delay: float) -> subprocess.Popen:
    """Launch `python -m <module> --target <target> --delay <delay>`."""
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    return subprocess.Popen(
        [sys.executable, "-m", module, "--target", str(target),
         "--delay", str(delay)],
        env=env,
    )


def worker_state(proc: subprocess.Popen) -> str:
    """Human-readable description of what has happened to the worker."""
    code = proc.poll()
    if code is None:
        try:
            status = psutil.Process(proc.pid).status()
        except psutil.NoSuchProcess:
            return "gone"
        if status in (psutil.STATUS_STOPPED, psutil.STATUS_TRACING_STOP):
            return "SUSPENDED"
        return "RUNNING"
    if code == 0:
        return "FINISHED (exited normally)"
    if code < 0:
        return f"KILLED by signal {-code}"
    return f"EXITED with code {code}"


def cleanup_worker(proc: subprocess.Popen) -> None:
    """Make sure the worker never outlives the launcher (resume first,
    because a SIGSTOPped process cannot act on SIGTERM until continued)."""
    if proc.poll() is not None:
        return
    try:
        p = psutil.Process(proc.pid)
        if p.status() == psutil.STATUS_STOPPED:
            p.resume()
        p.terminate()
    except psutil.NoSuchProcess:
        return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
