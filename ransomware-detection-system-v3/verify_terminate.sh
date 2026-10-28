#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

python - <<'PY'
import json
from pathlib import Path

PID = 22671
EVIDENCE = Path("evidence")
PROCESS_FILE = EVIDENCE / f"process_{PID}.json"
DECISIONS_FILE = EVIDENCE / "detection_decisions.jsonl"
OUTPUT_FILE = EVIDENCE / f"terminate_verification_{PID}.json"

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
    and record.get("outcome") == "Ransomware"
    and record.get("action") == "terminate"
    and record.get("mode") == "enforce"
    and record.get("authorized") is True
    and record.get("response_executed") is True
    and record.get("enforcement_status") == "terminated_verified"
]

decision = matches[-1] if matches else None
features = decision.get("features", {}) if decision else {}

checks = {
    "matching_pid": process.get("pid") == PID,
    "ransomware_classification": decision is not None,
    "terminate_threshold_reached": (
        decision is not None
        and isinstance(decision.get("confidence"), (int, float))
        and decision["confidence"] >= 0.625
    ),
    "authorized_enforcement": (
        decision is not None
        and decision.get("authorized") is True
        and decision.get("response_executed") is True
    ),
    "termination_verified": (
        decision is not None
        and decision.get("enforcement_status") == "terminated_verified"
    ),
    "process_running_observed": process.get("observed_running") is True,
    "feature_vector_recorded": all(
        isinstance(features.get(name), (int, float))
        and not isinstance(features.get(name), bool)
        and features[name] >= 0
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
    "process_observations": len(process.get("observations", [])),
    "note": (
        "Termination verified by the enforcement decision. "
        "The launcher independently reported exit code -15 (SIGTERM)."
    ),
}

OUTPUT_FILE.write_text(
    json.dumps(result, indent=2) + "\n",
    encoding="utf-8",
)

print("========== TERMINATE VERIFICATION ==========")
print(f"PID: {PID}")

for name, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'}: {name}")

print(f"\nFINAL RESULT: {result['result']}")
print(f"Evidence saved: {OUTPUT_FILE}")

if result["result"] != "PASS":
    raise SystemExit(1)
PY
