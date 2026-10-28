"""Independently record the state of a demonstration process."""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("--duration", type=float, default=20)
    args = parser.parse_args()

    output = ROOT / "evidence" / f"process_{args.pid}.json"
    output.parent.mkdir(exist_ok=True)

    observations = []
    deadline = time.monotonic() + args.duration

    try:
        process = psutil.Process(args.pid)
        create_time = process.create_time()
        command = process.cmdline()
    except psutil.Error as exc:
        print(f"Process unavailable: {exc}")
        return

    while time.monotonic() < deadline:
        try:
            current = psutil.Process(args.pid)

            if current.create_time() != create_time:
                break

            status = current.status()

            observations.append({
                "timestamp": timestamp(),
                "status": status,
                "running": status not in (
                    psutil.STATUS_ZOMBIE,
                    psutil.STATUS_DEAD,
                ),
            })

            if status in (
                psutil.STATUS_ZOMBIE,
                psutil.STATUS_DEAD,
            ):
                break

        except psutil.NoSuchProcess:
            break

        time.sleep(0.2)

    report = {
        "pid": args.pid,
        "command": command,
        "create_time": create_time,
        "observations": observations,
        "observed_running": any(
            item["running"] for item in observations
        ),
        "observed_suspended": any(
            item["status"] == psutil.STATUS_STOPPED
            for item in observations
        ),
        "last_observed_status": (
            observations[-1]["status"]
            if observations else None
        ),
    }

    output.write_text(json.dumps(report, indent=2))

    print(f"Process evidence saved: {output}")
    print(f"Running observed: {report['observed_running']}")
    print(f"Suspended observed: {report['observed_suspended']}")
    print(f"Last status: {report['last_observed_status']}")


if __name__ == "__main__":
    main()
