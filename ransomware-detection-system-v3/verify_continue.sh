#!/bin/bash
set -e
cd ~/ransomware-detection-system-v3
source /root/venv/bin/activate

python - <<'PY'
import json
from pathlib import Path
from datetime import datetime

evidence = Path("evidence")
records = [
    json.loads(line)
    for line in (evidence / "detection_decisions.jsonl").read_text().splitlines()
    if line.strip()
]

benign = [
    r for r in records
    if r["action"] == "continue"
    and r["outcome"].lower() == "benign"
]

if not benign:
    raise SystemExit("No benign CONTINUE detection found.")

latest = max(benign, key=lambda r: r["timestamp_utc"])
pid = latest["pid"]

decisions = sorted(
    [r for r in benign if r["pid"] == pid],
    key=lambda r: r["timestamp_utc"]
)

decision = decisions[0]
decision_time = datetime.fromisoformat(decision["timestamp_utc"])

process = json.loads(
    (evidence / f"process_{pid}.json").read_text()
)

running = [
    o for o in process["observations"]
    if o["running"]
    and datetime.fromisoformat(o["timestamp"]) > decision_time
]

duration = (
    datetime.fromisoformat(running[-1]["timestamp"]) - decision_time
).total_seconds() if running else 0

verified = bool(running) and not process["observed_suspended"]

report = {
    "pid": pid,
    "classification": decision["outcome"],
    "confidence": decision["confidence"],
    "action": "CONTINUE",
    "mode": decision["mode"],
    "decision_timestamp_utc": decision["timestamp_utc"],
    "running_observations_after_decision": len(running),
    "observed_running_duration_seconds": round(duration, 3),
    "suspension_observed": process["observed_suspended"],
    "verified": verified,
}

output = evidence / "continue_verification.json"
output.write_text(json.dumps(report, indent=2))

print("\n========== CONTINUE VERIFICATION ==========")
print("PID:", pid)
print("Classification:", report["classification"])
print("Confidence:", f"{report['confidence']:.2%}")
print("Action:", report["action"])
print("Mode:", report["mode"])
print("Running after decision:", bool(running))
print("Observed duration:", f"{duration:.2f} seconds")
print("Suspended:", report["suspension_observed"])
print("VERIFIED:", verified)
print("Evidence saved:", output)
PY
