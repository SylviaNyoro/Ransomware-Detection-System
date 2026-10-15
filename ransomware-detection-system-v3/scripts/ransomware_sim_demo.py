"""
Controlled ransomware-behaviour simulation -- QUARANTINE demonstration.

PURPOSE
-------
A CONTROLLED ACADEMIC TEST HARNESS -- not malware -- demonstrating that the
live Watchdog monitor and trained Random Forest flag ransomware-like
filesystem behaviour as suspicious and place it under QUARANTINE
(proposal Ch. 3.6: "ransomware-like activities carried out with the help
of a controlled encryption script").

HOW IT WORKS (launcher + worker)
--------------------------------
This script is the LAUNCHER.  It starts the live monitor and classifier,
then spawns scripts/ransomware_sim_worker.py as a SEPARATE OS PROCESS that
performs the file operations (6 files, 2 directories, XOR + '.locked').
Because the worker is its own process and holds each file open, psutil
attributes the activity to the worker's REAL PID -- the same design as
scripts/encryptor_worker.py.

WHAT HAPPENS TO THE WORKER
--------------------------
- This launcher's own detector is hardcoded to OBSERVE mode: it classifies
  and reports, and never suspends or kills anything itself.
- If the dashboard is running in ENFORCE mode and watching the same
  directory (use --live), the dashboard's backend will see the worker's PID
  and genuinely SUSPEND it (QUARANTINE).  This launcher then reports the
  worker's real state (RUNNING / SUSPENDED / KILLED) so you can show it.
- When the demo ends the launcher always resumes and stops the worker, so
  nothing is left frozen on your machine.
- For the real TERMINATE demonstration use scripts/encryptor_worker.py.
- If the classifier ever crosses the terminate threshold here, the
  launcher's own summary relabels it "quarantine-equivalent (capped)".

Run from the project root:
    python -m scripts.ransomware_sim_demo            # headless temp dir
    python -m scripts.ransomware_sim_demo --live     # data/decoy (dashboard sees it)
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

WORKER_MODULE = "scripts.ransomware_sim_worker"


def run_sim(target_dir: Path, delay: float, grace: float) -> dict:
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
    print("  RANSOMWARE SIM -- QUARANTINE demonstration")
    print("=" * 62)
    print(f"  Decoy directory   :  {target_dir}")
    print( "  Launcher mode     :  observe (launcher never acts on a process)")
    print( "  Worker            :  separate process with its own real PID")
    print( "  Real TERMINATE    :  run scripts/encryptor_worker.py")
    print("=" * 62)

    results: list[dict] = []
    worker = {"pid": None}
    skipped = {"unattributed": 0}
    stop_reason = {"triggered": False}

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
        if result["action"] != "continue":
            stop_reason["triggered"] = True

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

        # Wait until the classifier flags the worker, or the worker finishes.
        while proc.poll() is None and not stop_reason["triggered"]:
            time.sleep(0.1)

        if stop_reason["triggered"]:
            # Give the dashboard (if enforcing) time to act on the worker,
            # then report what really happened to it.
            time.sleep(grace)
            outcome = worker_state(proc)
        else:
            # Worker ran to completion; allow the final window to classify.
            deadline = time.time() + 6.0
            while time.time() < deadline and not stop_reason["triggered"]:
                time.sleep(0.1)
            outcome = worker_state(proc)
            if stop_reason["triggered"]:
                time.sleep(grace)
                outcome = worker_state(proc)
    finally:
        if proc is not None:
            cleanup_worker(proc)
        time.sleep(0.5)
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)

    # Keep results only up to and including the first non-continue result,
    # so the printed narrative never shows an escalation past the point the
    # run claims to have stopped at.
    trimmed: list[dict] = []
    for r in results:
        trimmed.append(r)
        if r["action"] != "continue":
            break

    return {"rows": trimmed,
            "worker_pid": proc.pid if proc is not None else None,
            "outcome": outcome,
            "unattributed": skipped["unattributed"]}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Controlled ransomware-behaviour simulation (launcher + "
            "attributable worker process). Launcher is observe-only; "
            "demonstrates QUARANTINE. For a real TERMINATE run "
            "scripts/encryptor_worker.py."
        )
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Use data/decoy/sim_ransomware instead of a temp dir, so the "
             "dashboard backend also sees (and can enforce on) the worker.")
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds the worker holds each file open per step (default 0.5).")
    parser.add_argument(
        "--grace", type=float, default=4.0,
        help="Seconds to wait after the first flag so the dashboard can "
             "act and the worker's real state can be shown (default 4).")
    args = parser.parse_args()

    if args.live:
        target = Path("data/decoy/sim_ransomware")
        target.mkdir(parents=True, exist_ok=True)
        info = run_sim(target, args.delay, args.grace)
    else:
        with tempfile.TemporaryDirectory(prefix="ransomware-sim-demo-") as tmp:
            info = run_sim(Path(tmp), args.delay, args.grace)

    rows, wpid = info["rows"], info["worker_pid"]

    print()
    print("=" * 62)
    print("  CLASSIFICATION RESULTS")
    print("=" * 62)
    if not rows:
        print("  No classification arrived before timeout.")
        print("  Check config.yaml paths and that models/ exists.")
    else:
        for r in rows:
            action = r["action"]
            display_action, note = action, ""
            if action == "terminate":
                display_action = "quarantine-equivalent (capped)"
                note = ("  -> capped for this demo; the launcher touched no "
                        "process. Run scripts/encryptor_worker.py for a real "
                        "TERMINATE.")
            label = "RANSOMWARE" if r["prediction"] == 1 else "goodware"
            model_confidence = r["confidence"]
            response_confidence = r.get(
                "response_confidence", model_confidence
            )
            bar = "#" * int(response_confidence * 20)
            match = ("  (matches worker)" if r["pid"] == wpid
                     else "  (NOT attributed to worker)")
            print(f"  PID        :  {r['pid']}{match}")
            print(f"  Prediction :  {label}  (class {r['prediction']})")
            print(f"  Model confidence    :  {model_confidence:.1%}")
            print(
                f"  Response-band score:  {response_confidence:.1%} "
                f"[{bar:<20}]"
            )
            print(f"  Action     :  {display_action.upper()}{note}")
            print(f"  Reaction   :  {r['reaction_time_ms']:.2f} ms")
            print(f"  Features   :  {r['features']}")

    print("-" * 62)
    print(f"  Worker PID     :  {wpid}")
    print(f"  Worker outcome :  {info['outcome']}")
    print(f"  Unattributed windows skipped :  {info['unattributed']}")
    print("    (SUSPENDED / KILLED = the dashboard in ENFORCE mode acted on")
    print("     this real PID.  RUNNING = nothing enforced; launcher is")
    print("     observe-only.  The launcher stops the worker on exit.)")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()


