"""Verify process suspension, resumption, and termination safely."""

import subprocess
import sys
import time

import psutil


def test_control_dedicated_process():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )

    target = psutil.Process(process.pid)

    try:
        assert target.is_running()
        print(f"\nStarted harmless test PID: {process.pid}")

        target.suspend()
        time.sleep(0.3)

        assert target.status() == psutil.STATUS_STOPPED
        print("QUARANTINE VERIFIED: process suspended")

        target.resume()
        time.sleep(0.3)

        assert target.status() != psutil.STATUS_STOPPED
        print("CONTINUE VERIFIED: process resumed")

        target.terminate()
        process.wait(timeout=5)

        assert not target.is_running() or target.status() == psutil.STATUS_ZOMBIE
        print("TERMINATION VERIFIED: process exited")

    finally:
        if process.poll() is None:
            target.resume()
            target.terminate()
            process.wait(timeout=5)
