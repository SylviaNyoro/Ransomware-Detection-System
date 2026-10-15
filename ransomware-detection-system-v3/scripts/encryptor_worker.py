"""
Standalone encryptor worker — the attributable target for a live
enforce-mode termination demo.

WHY THIS EXISTS
----------------
scripts/ransomware_sim_demo.py runs its file operations inline, in the
same Python process as the orchestration script.  Those operations
complete in milliseconds, and psutil's ProcessAttributor snapshots open
file handles on a ~1 second cycle -- fast enough that the handle is
already closed by the time a snapshot runs.  The event still gets
classified correctly, but there is no PID to act on, so enforce mode
cannot actually demonstrate a kill.

This script is the fix: it is launched as its OWN OS process (not a
thread, not inline code), and it holds each file open and writes to it
slowly, one file at a time, with a real delay between files.  That
gives ProcessAttributor's snapshot cycle time to catch this process
with the file handle genuinely open, so the live monitor can attribute
every event to this process's real PID -- and enforce mode can
terminate it for real.

SCOPE LIMITS (same as ransomware_sim_demo.py)
-----------------------------------------------
- Operates only inside the directory passed as --target, which the
  caller is expected to have created as a throwaway decoy directory.
- XOR encryption only -- single-byte key printed to stdout before any
  file is touched, so every file is trivially recoverable.
- No network calls, no persistence, no spreading, no privilege
  escalation. The only capability is: open a file in this directory,
  overwrite its bytes, rename it.
- This process is expected to be killed by the detection system before
  it finishes. That is the point of the demo.

USAGE
-----
    python -m scripts.encryptor_worker --target data/decoy/sim_kill [--delay 0.6]

Run this WHILE the dashboard is monitoring the same watched directory,
in enforce mode, with a trained model whose terminate threshold the
live confidence is expected to cross.
"""
from __future__ import annotations

import argparse
import secrets
import sys
import time
from pathlib import Path

# Same realistic decoy content used by ransomware_sim_demo.py, so the
# behavioral signal (file count, directory spread, renamed extensions)
# is comparable between the two demos.
_DECOY_FILES: list[tuple[str, str, str]] = [
    ("docs",     "financial_report_q3.txt",
     "Q3 Financial Report\nRevenue: $4.2M\nExpenses: $2.1M\nNet: $2.1M\n"),
    ("docs",     "contract_vendor_2026.txt",
     "Vendor Agreement\nParties: Acme Corp / WidgetCo\nTerm: 12 months\n"),
    ("docs",     "meeting_minutes_oct.txt",
     "Meeting: 2026-10-01\nAttendees: Alice, Bob, Carol\nActions: ...\n"),
    ("finance",  "budget_2026.csv",
     "Category,Allocated,Spent\nSalaries,200000,185000\nOps,50000,43000\n"),
    ("finance",  "invoices_q3.csv",
     "Invoice,Amount,Status\nINV-001,5000,Paid\nINV-002,3200,Pending\n"),
    ("finance",  "payroll_oct.csv",
     "EmployeeID,Name,Gross\n1001,Alice,4500\n1002,Bob,4200\n"),
    ("hr",       "employee_directory.txt",
     "ID,Name,Department\n1001,Alice,Engineering\n1002,Bob,Finance\n"),
    ("hr",       "onboarding_checklist.txt",
     "New-hire checklist\n[x] ID badge\n[x] Laptop\n[ ] Security training\n"),
    ("hr",       "leave_policy.txt",
     "Annual Leave Policy\nEntitlement: 21 days/year\nCarryover: max 5 days\n"),
    ("projects", "roadmap_2027.txt",
     "Project Phoenix - Roadmap\nPhase 1: Q1 2027\nPhase 2: Q3 2027\n"),
    ("projects", "specs_auth_module.txt",
     "Auth Module Specification\nOAuth2 + PKCE\nToken lifetime: 1h\n"),
    ("projects", "timeline_phoenix.csv",
     "Milestone,Deadline,Owner\nDesign,2027-01-15,Alice\nBuild,2027-03-01,Bob\n"),
    ("admin",    "server_config.txt",
     "Server: prod-01\nOS: Ubuntu 24.04\nServices: nginx, postgres\n"),
    ("admin",    "backup_log.txt",
     "2026-10-01 02:00 -- backup OK  (14 GB)\n2026-10-02 02:00 -- backup OK\n"),
    ("admin",    "it_notes.txt",
     "IT Notes\n- Patch servers by Friday\n- Rotate TLS certs in Nov\n"),
]

_EXTS = [".locked", ".enc"]


def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Slow, attributable XOR encryptor for a live "
                    "enforce-mode termination demo."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Decoy directory to operate in (created if missing). "
             "Must be the directory the dashboard is watching.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.6,
        help="Seconds to hold each file open before moving to the next "
             "one (default: 0.6s). Lower is faster but gives "
             "ProcessAttributor less time to snapshot this process.",
    )
    args = parser.parse_args()

    target_dir = Path(args.target)
    target_dir.mkdir(parents=True, exist_ok=True)

    key = secrets.randbelow(256)
    pid = __import__("os").getpid()

    print()
    print("=" * 62)
    print("  ENCRYPTOR WORKER -- attributable live-kill demo process")
    print("=" * 62)
    print(f"  This process PID    :  {pid}")
    print(f"  XOR encryption key  :  0x{key:02X}  ({key})")
    print(f"  Decrypt any file    :  bytes(b ^ 0x{key:02X} for b in data)")
    print(f"  Decoy directory     :  {target_dir}")
    print(f"  Per-file delay      :  {args.delay}s")
    print("=" * 62)
    print()
    print(f"  If the dashboard is monitoring '{target_dir}' in enforce "
          f"mode, this process is expected to be terminated partway "
          f"through the file list below.")
    print()

    subdirs = sorted({row[0] for row in _DECOY_FILES})
    for sub in subdirs:
        (target_dir / sub).mkdir(parents=True, exist_ok=True)

    files_done = 0
    try:
        for subdir, name, content in _DECOY_FILES:
            path = target_dir / subdir / name

            # Hold ONE continuous handle open across create + encrypt
            # for the full --delay window, rather than closing and
            # reopening between steps. A single long window gives the
            # live monitor's periodic process snapshot (ProcessAttributor,
            # polled roughly once per config.yaml's poll_interval_seconds)
            # the best chance of catching this PID with the file
            # genuinely open -- closing and reopening between every
            # step creates gaps a 1Hz poll can fall into and miss.
            with open(path, "w+b") as fh:
                fh.write(content.encode("utf-8"))
                fh.flush()
                print(f"  [{files_done + 1:02d}/{len(_DECOY_FILES)}] "
                      f"created  {subdir}/{name}  (PID {pid} holding handle)")
                time.sleep(args.delay)

                fh.seek(0)
                plaintext = fh.read()
                ciphertext = xor_encrypt(plaintext, key)
                fh.seek(0)
                fh.truncate()
                fh.write(ciphertext)
                fh.flush()
                print(f"           encrypted  {subdir}/{name}  "
                      f"(PID {pid} still holding handle)")
                time.sleep(args.delay)

            ext = _EXTS[files_done % len(_EXTS)]
            locked = path.with_suffix(ext)
            path.rename(locked)
            print(f"           renamed    {subdir}/{name} -> {locked.name}")

            files_done += 1

        print()
        print(f"  Finished: all {files_done} files encrypted and renamed "
              f"without being stopped.")
        print(f"  (If you expected a TERMINATE, check that the dashboard "
              f"is in ENFORCE mode and watching '{target_dir}'.)")

    except KeyboardInterrupt:
        print(f"\n  Stopped manually after {files_done} file(s).")
    finally:
        # SIGTERM from psutil.terminate() raises SystemExit via the
        # default handler; this block still runs on normal interpreter
        # shutdown paths and prints a clear summary either way.
        print()
        print("=" * 62)
        print(f"  Files completed before this process ended: {files_done} "
              f"of {len(_DECOY_FILES)}")
        print(f"  Decryption key for any files already changed: 0x{key:02X}")
        print("=" * 62)


if __name__ == "__main__":
    main()
