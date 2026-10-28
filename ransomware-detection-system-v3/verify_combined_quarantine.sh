#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

python - <<'PY'
import json
from pathlib import Path

PID = 22418
EVIDENCE = Path("evidence")
PROCESS_FILE = EVIDENCE / f"process_{PID}.json"
DECISIONS_FILE = EVIDENCE / "detection_decisions.jsonl"
OUTPUT_FILE = EVIDENCE / f"quarantine_verification_{PID}.json"

FEATURES = (
    "changed_file_count",
    "file_access_breadth",
    "directory_traversal_breadth",
    "file_creation_count",
    "file_deletion_count",
    "extension_diversity",
    "file_activity_total",
)

process = json.loads(PROCESS_FILE.read_text())

decisions = [
    json.loads(line)
    for line in DECISIONS_FILE.read_text().splitlines()
    if line.strip()
]

matches = [
    record for record in decisions
    if record.get("pid") == PID
    and record.get("action") == "quarantine"
    and record.get("mode") == "enforce"
    and record.get("authorized") is True
    and record.get("response_executed") is True
    and record.get("enforcement_status") == "suspended_verified"
]

decision = matches[-1] if matches else None
features = decision.get("features", {}) if decision else {}

observations = process.get("observations", [])
statuses = [entry.get("status") for entry in observations]

suspended_indices = [
    index for index, status in enumerate(statuses)
    if status == "stopped"
]

suspension_observed = bool(suspended_indices)

recovery_observed = (
    any(
        status not in {"stopped", "zombie", "dead", None}
        for status in statuses[suspended_indices[0] + 1:]
    )
    if suspension_observed else False
)

checks = {
    "matching_pid": process.get("pid") == PID,
    "quarantine_decision_verified": decision is not None,
    "process_running_observed": process.get("observed_running") is True,
    "process_suspension_observed": (
        process.get("observed_suspended") is True
        and suspension_observed
    ),
    "process_recovery_observed": recovery_observed,
    "all_seven_features_present": all(
        isinstance(features.get(name), (int, float))
        and not isinstance(features.get(name), bool)
        and features[name] > 0
        for name in FEATURES
    ),
}

result = {
    "pid": PID,
    "result": "PASS" if all(checks.values()) else "FAIL",
    "checks": checks,
    "classification": decision.get("outcome") if decision else None,
    "confidence": decision.get("confidence") if decision else None,
    "action": decision.get("action") if decision else None,
    "enforcement_status": (
        decision.get("enforcement_status") if decision else None
    ),
    "features": features,
    "observation_count": len(observations),
    "suspension_observed": suspension_observed,
    "recovery_observed": recovery_observed,
}

OUTPUT_FILE.write_text(json.dumps(result, indent=2) + "\n")

print("========== COMBINED QUARANTINE VERIFICATION ==========")
print(f"PID: {PID}")

for name, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'}: {name}")

print(f"\nFINAL RESULT: {result['result']}")
print(f"Evidence saved: {OUTPUT_FILE}")

if result["result"] != "PASS":
    raise SystemExit(1)
PY
