"""Verify filesystem integrity after the controlled TERMINATE demonstration."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
PID = 23035

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot(paths):
    result = {}
    for name in paths:
        path = ROOT / name
        if path.is_file():
            result[name] = {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        else:
            result[name] = None
    return result

before = json.loads(
    (EVIDENCE / "terminate_integrity_before.json").read_text()
)

demo_before = before["demo_files"]
control_before = before["control_files"]

demo_after = snapshot(demo_before)
control_after = snapshot(control_before)

modified = [
    name for name in demo_before
    if demo_after[name] is not None
    and demo_before[name]["sha256"] != demo_after[name]["sha256"]
]

unchanged = [
    name for name in demo_before
    if demo_after[name] is not None
    and demo_before[name]["sha256"] == demo_after[name]["sha256"]
]

missing = [
    name for name in demo_before
    if demo_after[name] is None
]

controls_intact = (
    len(control_before) == 5
    and all(
        control_after[name] == control_before[name]
        for name in control_before
    )
)

decisions = [
    json.loads(line)
    for line in (EVIDENCE / "detection_decisions.jsonl").read_text().splitlines()
    if line.strip()
]

matches = [
    record for record in decisions
    if record.get("pid") == PID
    and record.get("action") == "terminate"
    and record.get("authorized") is True
    and record.get("response_executed") is True
    and record.get("enforcement_status") == "terminated_verified"
]

decision = matches[0] if matches else None

process = json.loads(
    (EVIDENCE / f"process_{PID}.json").read_text()
)

checks = {
    "baseline_contains_96_files": len(demo_before) == 96,
    "all_demo_files_accounted_for": not missing,
    "five_control_files_unchanged": controls_intact,
    "termination_enforcement_verified": decision is not None,
    "process_running_observed": process.get("observed_running") is True,
}

result = {
    "pid": PID,
    "baseline_timestamp": before["captured_at_utc"],
    "comparison_timestamp": datetime.now(timezone.utc).isoformat(),
    "demo_files_total": len(demo_before),
    "demo_files_modified": len(modified),
    "demo_files_unchanged": len(unchanged),
    "demo_files_missing": missing,
    "modified_files": modified,
    "control_files_total": len(control_before),
    "control_files_intact": controls_intact,
    "checks": checks,
    "verification": "PASS" if all(checks.values()) else "FAIL",
    "termination_decision": decision,
    "limitations": [
        "Hash differences prove content changes, not encryption.",
        "Modified-file count is not necessarily the number of completed write operations.",
        "Termination does not reverse modifications made before SIGTERM.",
        "A single post-execution snapshot cannot independently prove when activity stopped.",
        "Control-file integrity applies only to the five selected control files.",
    ],
}

output = EVIDENCE / f"terminate_integrity_verification_{PID}.json"
output.write_text(json.dumps(result, indent=2) + "\n")

print("========== TERMINATE FILE-INTEGRITY VERIFICATION ==========")
print(f"PID: {PID}")
print(f"Files modified: {len(modified)} / {len(demo_before)}")
print(f"Files unchanged: {len(unchanged)}")
print(f"Files missing: {len(missing)}")
print(f"Control files intact: {controls_intact}")

for name, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'}: {name}")

print(f"\nFINAL RESULT: {result['verification']}")
print(f"Evidence saved: {output}")

if result["verification"] != "PASS":
    raise SystemExit(1)
