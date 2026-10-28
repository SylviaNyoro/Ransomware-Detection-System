import subprocess
import sys
import time

import psutil

print("Starting harmless test process...")

process = subprocess.Popen([
    sys.executable,
    "-c",
    "import time; time.sleep(60)"
])

try:
    target = psutil.Process(process.pid)

    print(f"Test PID: {process.pid}")
    print("Applying quarantine (process suspension)...")

    target.suspend()
    time.sleep(1)

    status = target.status()
    suspended = status == psutil.STATUS_STOPPED

    print(f"Process status: {status}")
    print(f"Quarantine successful: {suspended}")

    if not suspended:
        raise RuntimeError("Process was not confirmed suspended")

    print("Resuming test process...")
    target.resume()
    time.sleep(1)

    resumed_status = target.status()
    print(f"Status after resume: {resumed_status}")

    if resumed_status == psutil.STATUS_STOPPED:
        raise RuntimeError("Process did not resume")

    print("QUARANTINE RESPONSE TEST PASSED")

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
