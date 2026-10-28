#!/bin/bash
set -euo pipefail

python - <<'PY'
import json
from pathlib import Path
from datetime import datetime

pid = 16493
process_path = Path(f"evidence/process_{pid}.json")
decisions_path = Path("evidence/detection_decisions.jsonl")
output_path = Path("evidence/quarantine_verification.json")

if not process_path.exists():
    raise SystemExit("ERROR: Process evidence not found.")

if not decisions_path.exists():
    raise SystemExit("ERROR: Detection decisions not found.")

process = json.loads(process_path.read_text())
observations = process.get("observations", [])

decisions = [
    json.loads(line)
    for line in decisions_path.read_text().splitlines()
    if line.strip()
]

matches = [
    record for record in decisions
    if record.get("pid") == pid
    and str(record.get("action", "")).upper() == "QUARANTINE"
]

print("========== QUARANTINE VERIFICATION ==========")
print("PID:", pid)

if not matches:
    raise SystemExit("ERROR: No QUARANTINE decision found for this PID.")

decision = next(
    (
        record for record in matches
        if record.get("response_executed") is True
        and record.get("enforcement_status") == "suspended_verified"
    ),
    matches[0],
)

statuses = [o.get("status") for o in observations]

suspended_indices = [
    i for i, status in enumerate(statuses)
    if status == "stopped"
]

suspension_observed = bool(suspended_indices)

recovery_observed = False
suspension_duration = None

if suspension_observed:
    first = suspended_indices[0]

    recovery_index = next(
        (
            i for i in range(first + 1, len(observations))
            if observations[i].get("status")
            not in ("stopped", "zombie", "dead", None)
        ),
        None,
    )

    if recovery_index is not None:
        recovery_observed = True

        start = datetime.fromisoformat(
            observations[first]["timestamp"]
        )
        end = datetime.fromisoformat(
            observations[recovery_index]["timestamp"]
        )

        suspension_duration = round(
            (end - start).total_seconds(), 3
        )

verified = all([
    str(decision.get("action", "")).upper() == "QUARANTINE",
    decision.get("mode") == "enforce",
    decision.get("authorized") is True,
    decision.get("response_executed") is True,
    decision.get("enforcement_status") == "suspended_verified",
    suspension_observed,
    recovery_observed,
])

report = {
    "pid": pid,
    "classification": decision.get("outcome"),
    "confidence": decision.get("confidence"),
    "action": decision.get("action"),
    "mode": decision.get("mode"),
    "authorized": decision.get("authorized"),
    "response_executed": decision.get("response_executed"),
    "enforcement_status": decision.get("enforcement_status"),
    "suspension_observed": suspension_observed,
    "recovery_observed": recovery_observed,
    "observed_suspension_duration_seconds": suspension_duration,
    "verified": verified,
}

output_path.write_text(json.dumps(report, indent=2) + "\n")

for key, value in report.items():
    print(f"{key}: {value}")

print("Evidence saved:", output_path)

if not verified:
    raise SystemExit("VERIFICATION INCOMPLETE")
PY
