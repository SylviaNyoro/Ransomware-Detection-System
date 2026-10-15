"""
Goodware (normal-user-activity) simulation -- CONTINUE / benign demonstration.

PURPOSE
-------
Complement to ransomware_sim_demo.py: benign filesystem operations that the
trained Random Forest should classify as goodware -- low ransomware
confidence, "continue" action.

RUN ORDER FOR THE VIVA: this script (CONTINUE), then ransomware_sim_demo.py
(QUARANTINE), then scripts/encryptor_worker.py (real TERMINATE).

HOW IT WORKS (launcher + worker)
--------------------------------
This script is the LAUNCHER.  It starts the live monitor and classifier,
then spawns scripts/goodware_worker.py as a SEPARATE OS PROCESS that does
the file operations.  Because the worker is its own process and holds each
file open, psutil attributes the activity to the worker's REAL PID -- the
same design as scripts/encryptor_worker.py.

The launcher's detector is hardcoded to OBSERVE mode, so it never touches
a process.  If the dashboard is in ENFORCE mode and watching the same
directory (--live) and the small training corpus misclassifies this benign
activity (a documented limitation, Ch. 5), the dashboard could act on the
worker; the launcher reports the worker's real final state either way and
always stops the worker on exit.  Terminate-level results are relabeled
"quarantine-equivalent (capped)" in the launcher's own summary.

Run from the project root:
    python -m scripts.goodware_demo           # headless temp dir
    python -m scripts.goodware_demo --live    # data/decoy (dashboard sees it)
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts._demo_common import cleanup_worker, spawn_worker, worker_state
from src.live_detection import create_live_detector
from src.monitor.watcher import start_monitor

WORKER_MODULE = "scripts.goodware_worker"


def run_goodware(target_dir: Path, delay: float) -> dict:
    """Run launcher + worker; return results, worker PID and worker outcome."""
    # Absolute path: the monitor matches watchdog event paths against the
    # absolute paths psutil reports for open files, so a relative path
    # would defeat PID attribution.
    target_dir = Path(target_dir).resolve()

    if not Path("config.yaml").exists():
        sys.exit("ERROR: run from the project root (where config.yaml lives).")

    with open("config.yaml", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    detector = create_live_detector(cfg)
    detector.response_mode = "observe"   # hardcoded: the launcher never enforces

    print()
    print("=" * 62)
    print("  GOODWARE SIM -- normal user activity (CONTINUE demonstration)")
    print("=" * 62)
    print(f"  Directory         :  {target_dir}")
    print( "  Launcher mode     :  observe (launcher never acts on a process)")
    print( "  Worker            :  separate process with its own real PID")
    print("=" * 62)

    results: list[dict] = []
    worker = {"pid": None}
    skipped = {"unattributed": 0}

    def on_features(pid, fv):
        # The first event on each file can land before the monitor's
        # process snapshot sees the new handle (pid -1).  Those windows
        # are counted but not classified/acted on here; the demo is about
        # activity attributed to the worker's real PID.
        if worker["pid"] is not None and pid != worker["pid"]:
            skipped["unattributed"] += 1
            return
        t0 = time.perf_counter()
        result = detector.on_features(pid, fv)
        rt_ms = (time.perf_counter() - t0) * 1000
        results.append({**result, "reaction_time_ms": rt_ms,
                        "features": fv.as_dict()})

    observer, stop_event = start_monitor(
        watched_directories=[str(target_dir)],
        common_extensions=cfg["features"]["common_extensions"],
        poll_interval_seconds=0.3,
        window_seconds=cfg["monitor"].get("window_seconds", 10.0),
        on_features=on_features,
    )

    proc = None
    outcome = "not started"
    try:
        time.sleep(0.5)
        proc = spawn_worker(WORKER_MODULE, target_dir, delay)
        worker["pid"] = proc.pid
        # Wait for the worker to finish -- or stop waiting if the dashboard
        # (enforce mode) suspends it after a false positive, which would
        # otherwise leave us waiting on a frozen process forever.
        t_end = time.time() + 120.0
        while proc.poll() is None and time.time() < t_end:
            if worker_state(proc) == "SUSPENDED":
                print("\n[!]    Worker was SUSPENDED by the dashboard "
                      "(false positive on benign activity).")
                break
            time.sleep(0.2)
        print("\n[...]  Waiting for classifier ...")
        time.sleep(2.0)
        outcome = worker_state(proc)
    finally:
        if proc is not None:
            cleanup_worker(proc)
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)

    return {"rows": results,
            "worker_pid": proc.pid if proc is not None else None,
            "outcome": outcome,
            "unattributed": skipped["unattributed"]}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normal-user-activity simulation (launcher + attributable "
            "worker process). Launcher is observe-only; demonstrates "
            "CONTINUE."
        )
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Use data/decoy/sim_goodware instead of a temp dir, so the "
             "dashboard backend also sees the worker.")
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds the worker holds each file open (default 0.5).")
    args = parser.parse_args()

    if args.live:
        target = Path("data/decoy/sim_goodware")
        target.mkdir(parents=True, exist_ok=True)
        info = run_goodware(target, args.delay)
    else:
        with tempfile.TemporaryDirectory(prefix="goodware-demo-") as tmp:
            info = run_goodware(Path(tmp), args.delay)

    rows, wpid = info["rows"], info["worker_pid"]

    print()
    print("=" * 62)
    print("  CLASSIFICATION RESULTS")
    print("=" * 62)
    if not rows:
        print("  No detection fired -- classifier stayed silent.")
        print("  Expected for benign activity: nothing crossed the threshold.")
    else:
        for r in rows:
            action = r["action"]
            display_action, note = action, ""
            if action == "terminate":
                display_action = "quarantine-equivalent (capped)"
                note = ("  -> capped for this demo; the launcher touched no "
                        "process. Reflects the small-corpus false-positive "
                        "limitation documented in Ch. 5.")
            label = "RANSOMWARE" if r["prediction"] == 1 else "goodware"
            bar = "#" * int(r["confidence"] * 20)
            match = ("  (matches worker)" if r["pid"] == wpid
                     else "  (NOT attributed to worker)")
            print(f"  PID        :  {r['pid']}{match}")
            print(f"  Prediction :  {label}  (class {r['prediction']})")
            print(f"  Confidence :  {r['confidence']:.1%}  [{bar:<20}]")
            print(f"  Action     :  {display_action.upper()}{note}")
            print(f"  Reaction   :  {r['reaction_time_ms']:.2f} ms")
            print(f"  Features   :  {r['features']}")

    print("-" * 62)
    print(f"  Worker PID     :  {wpid}")
    print(f"  Worker outcome :  {info['outcome']}")
    print(f"  Unattributed windows skipped :  {info['unattributed']}")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()
