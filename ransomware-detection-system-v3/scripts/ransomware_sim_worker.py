"""
Ransomware-simulation WORKER -- the attributable process behind the
QUARANTINE demonstration.

Launched by scripts/ransomware_sim_demo.py as its own OS process so that
psutil can attribute its file activity to a real PID (the same reason
scripts/encryptor_worker.py exists).  It performs the small-footprint,
ransomware-like sequence the demo is built around -- 6 files in 2
directories, XOR "encryption", one unusual extension (.locked) -- and
holds ONE file handle open per file for the whole create -> encrypt ->
rename sequence so the monitor's ~1 Hz process snapshot can catch it.

SCOPE LIMITS
------------
- Only touches files it creates itself inside --target (a throwaway
  decoy directory).
- Single-byte XOR; the key is printed before any file is touched.
- No network, no persistence, no spreading, no privilege escalation.
- It is EXPECTED to be suspended (quarantined) or stopped by the
  launcher / dashboard partway through.

Normally run via:  python -m scripts.ransomware_sim_demo [--live]
Direct use:        python -m scripts.ransomware_sim_worker --target DIR [--delay 0.5]
"""
from __future__ import annotations

import argparse
import os
import secrets
import time
from pathlib import Path

_DECOY_FILES: list[tuple[str, str, str]] = [
    ("docs",    "financial_report_q3.txt",
     "Q3 Financial Report\nRevenue: $4.2M\nExpenses: $2.1M\nNet: $2.1M\n"),
    ("docs",    "contract_vendor_2026.txt",
     "Vendor Agreement\nParties: Acme Corp / WidgetCo\nTerm: 12 months\n"),
    ("docs",    "meeting_minutes_oct.txt",
     "Meeting: 2026-10-01\nAttendees: Alice, Bob, Carol\nActions: ...\n"),
    ("finance", "budget_2026.csv",
     "Category,Allocated,Spent\nSalaries,200000,185000\nOps,50000,43000\n"),
    ("finance", "invoices_q3.csv",
     "Invoice,Amount,Status\nINV-001,5000,Paid\nINV-002,3200,Pending\n"),
    ("finance", "payroll_oct.csv",
     "EmployeeID,Name,Gross\n1001,Alice,4500\n1002,Bob,4200\n"),
]

_EXT = ".locked"


def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attributable ransomware-simulation worker "
                    "(QUARANTINE demo).")
    parser.add_argument("--target", required=True,
                        help="Decoy directory to operate in.")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to hold each file open per step "
                             "(default 0.5).")
    args = parser.parse_args()

    target = Path(args.target)
    target.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    key = secrets.randbelow(256)

    print()
    print("=" * 62)
    print("  RANSOMWARE SIM WORKER -- attributable QUARANTINE demo process")
    print("=" * 62)
    print(f"  Worker PID          :  {pid}")
    print(f"  XOR encryption key  :  0x{key:02X}  ({key})")
    print(f"  Decrypt any file    :  bytes(b ^ 0x{key:02X} for b in data)")
    print(f"  Decoy directory     :  {target}")
    print(f"  Per-step delay      :  {args.delay}s")
    print("=" * 62)
    print()

    for sub in sorted({row[0] for row in _DECOY_FILES}):
        (target / sub).mkdir(parents=True, exist_ok=True)

    done = 0
    try:
        for subdir, name, content in _DECOY_FILES:
            path = target / subdir / name
            total = len(_DECOY_FILES)
            # ONE handle held open across create + encrypt + rename.
            with open(path, "w+b") as fh:
                fh.write(content.encode("utf-8"))
                fh.flush()
                print(f"  [{done + 1}/{total}] created    {subdir}/{name}"
                      f"  (PID {pid} holding handle)")
                time.sleep(args.delay)

                fh.seek(0)
                data = fh.read()
                fh.seek(0)
                fh.truncate()
                fh.write(xor_encrypt(data, key))
                fh.flush()
                print(f"        encrypted  {subdir}/{name}")
                time.sleep(args.delay)

                locked = path.with_suffix(_EXT)
                path.rename(locked)      # handle stays open across rename
                print(f"        renamed    {subdir}/{name} -> {locked.name}")
                time.sleep(args.delay)
            done += 1
        print(f"\n  Finished all {done} files without being stopped.")
    except KeyboardInterrupt:
        print(f"\n  Stopped manually after {done} file(s).")
    finally:
        print()
        print("=" * 62)
        print(f"  Files completed before this process ended: {done} of "
              f"{len(_DECOY_FILES)}")
        print(f"  Decryption key for any files already changed: 0x{key:02X}")
        print("=" * 62)


if __name__ == "__main__":
    main()
