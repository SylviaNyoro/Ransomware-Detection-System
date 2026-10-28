"""Launch and supervise authorized, harmless demonstration processes."""

import argparse
import json
import threading
import subprocess
import sys
import time
from pathlib import Path

import psutil


ROOT = Path(__file__).resolve().parents[1]
AUTH_DIR = ROOT / "data" / "demo_authorization"

DEMOS = {
    "benign": ["bash", str(ROOT / "benign.sh")],
    "quarantine": ["bash", str(ROOT / "quarantine.sh")],
    "ransomware": [
        sys.executable,
        str(ROOT / "ransomware_classification_demo.py"),
    ],
    "creation_deletion": [
        sys.executable,
        str(ROOT / "test_creation_deletion.py"),
    ],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("demo", choices=DEMOS)
    args = parser.parse_args()

    AUTH_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Launching {args.demo} demonstration...", flush=True)

    process = subprocess.Popen(DEMOS[args.demo], cwd=ROOT)
    target = psutil.Process(process.pid)

    identity = {
        "pid": process.pid,
        "create_time": target.create_time(),
        "demo": args.demo,
        "authorized_at": time.time(),
    }

    registration = AUTH_DIR / f"{process.pid}.json"
    registration.write_text(json.dumps(identity), encoding="utf-8")

    print(f"Registered demonstration PID: {process.pid}", flush=True)

    # Independently sample the child process throughout the demonstration.
    evidence_process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.process_evidence",
            str(process.pid),
            "--duration",
            "45",
        ],
        cwd=ROOT,
    )

    suspended_at = None

    try:
        while process.poll() is None:
            try:
                if target.status() == psutil.STATUS_STOPPED:
                    if suspended_at is None:
                        suspended_at = time.monotonic()
                        print(
                            f"QUARANTINE VERIFIED: PID {process.pid} suspended",
                            flush=True,
                        )

                    elif time.monotonic() - suspended_at >= 15:
                        target.resume()
                        print(
                            f"RECOVERY: PID {process.pid} resumed",
                            flush=True,
                        )
                        suspended_at = None

                else:
                    suspended_at = None

            except psutil.NoSuchProcess:
                break

            time.sleep(0.2)

        exit_code = process.wait(timeout=5)

        print(f"PROCESS EXIT CODE: {exit_code}", flush=True)
        print(f"PROCESS PID: {process.pid}", flush=True)

        if exit_code == 0:
            print("PROCESS RESULT: NORMAL COMPLETION", flush=True)
        elif exit_code < 0:
            print(
                f"PROCESS RESULT: TERMINATED BY SIGNAL {-exit_code}",
                flush=True,
            )
        else:
            print("PROCESS RESULT: NONZERO EXIT", flush=True)

        try:
            evidence_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            evidence_process.terminate()
            evidence_process.wait(timeout=5)

        return exit_code

    finally:
        if process.poll() is None:
            try:
                if target.status() == psutil.STATUS_STOPPED:
                    target.resume()
            except psutil.Error:
                pass

        registration.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
