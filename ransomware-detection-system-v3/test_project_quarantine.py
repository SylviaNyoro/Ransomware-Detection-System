import subprocess
import sys
import time

import psutil

from src.response.responder import act_on_classification

process = subprocess.Popen([
    sys.executable,
    "-c",
    "import time; time.sleep(60)"
])

try:
    target = psutil.Process(process.pid)

    print(f"Test PID: {process.pid}")

    action = act_on_classification(
        process_id=process.pid,
        confidence=0.5095,
        quarantine_threshold=0.50,
        terminate_threshold=0.85,
        enforce=True,
    )

    time.sleep(0.5)

    suspended = target.status() == psutil.STATUS_STOPPED

    print(f"Response decision: {action}")
    print(f"Process suspended: {suspended}")

    assert action == "quarantine"
    assert suspended

    print("PROJECT QUARANTINE TEST PASSED")

finally:
    if process.poll() is None:
        try:
            psutil.Process(process.pid).resume()
        except psutil.Error:
            pass

        process.terminate()

        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
