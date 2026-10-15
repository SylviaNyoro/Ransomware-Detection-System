"""
Goodware (normal user activity) WORKER -- the attributable process behind
the CONTINUE / benign demonstration.

Launched by scripts/goodware_demo.py as its own OS process so that psutil
can attribute its file activity to a real PID (same design as
scripts/encryptor_worker.py).  Each file is held open for --delay seconds
while it is being "worked on", so the monitor's ~1 Hz snapshot can catch
the process with the handle open.

OPERATIONS
----------
1. Create two working documents (.txt).
2. Edit one (append a paragraph).
3. Write a session log (.log).
4. Extract a small zip archive ("email attachment") into one sub-folder.
5. Copy a finished document into an archive sub-folder.

Only touches files it creates itself inside --target. No network, no
persistence.

Normally run via:  python -m scripts.goodware_demo [--live]
Direct use:        python -m scripts.goodware_worker --target DIR [--delay 0.5]
"""
from __future__ import annotations

import argparse
import io
import os
import time
import zipfile
from pathlib import Path

_INITIAL_DOCS = {
    "report_draft.txt": (
        "Project Report - Draft\n"
        "======================\n"
        "Section 1: Introduction\n"
        "This document describes the project scope and objectives.\n"
        "The work is expected to be completed by end of Q4 2026.\n"
    ),
    "task_list.txt": (
        "To-Do List\n"
        "----------\n"
        "[ ] Finish literature review\n"
        "[ ] Collect dataset\n"
        "[ ] Write methodology chapter\n"
        "[ ] Submit first draft\n"
    ),
}

_EDIT_APPEND = (
    "\nSection 2: Methodology\n"
    "----------------------\n"
    "Data was collected from the enterprise environment over a 30-day period.\n"
    "All samples were labelled by a certified security analyst.\n"
)

_ARCHIVE_FILES = {
    "attachment/readme.txt":       "Attachment README\nExtracted automatically.\n",
    "attachment/summary_data.csv": "Metric,Value\nAccuracy,0.96\nPrecision,0.94\n",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attributable normal-user-activity worker "
                    "(CONTINUE / benign demo).")
    parser.add_argument("--target", required=True,
                        help="Directory to operate in.")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to hold each file open (default 0.5).")
    args = parser.parse_args()

    target = Path(args.target)
    target.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    d = args.delay

    print()
    print("=" * 62)
    print("  GOODWARE WORKER -- attributable benign-activity process")
    print("=" * 62)
    print(f"  Worker PID       :  {pid}")
    print(f"  Directory        :  {target}")
    print(f"  Per-file delay   :  {d}s")
    print("=" * 62)
    print()

    print("[1/5]  Creating working documents ...")
    for name, content in _INITIAL_DOCS.items():
        with open(target / name, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            print(f"       + {name}   (PID {pid} holding handle)")
            time.sleep(d)

    print("\n[2/5]  Editing report_draft.txt ...")
    with open(target / "report_draft.txt", "a", encoding="utf-8") as fh:
        fh.write(_EDIT_APPEND)
        fh.flush()
        print(f"       appended {len(_EDIT_APPEND)} bytes")
        time.sleep(d)

    print("\n[3/5]  Writing session.log ...")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(target / "session.log", "w", encoding="utf-8") as fh:
        fh.write(f"[{ts}] User session started\n"
                 f"[{ts}] Opened report_draft.txt\n"
                 f"[{ts}] Saved report_draft.txt\n"
                 f"[{ts}] Opened task_list.txt\n")
        fh.flush()
        print("       + session.log")
        time.sleep(d)

    print("\n[4/5]  Extracting email attachment (zip) ...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, body in _ARCHIVE_FILES.items():
            zf.writestr(arc, body)
    buf.seek(0)
    with zipfile.ZipFile(buf, "r") as zf:
        for arc in zf.namelist():
            dest = target / arc
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(zf.read(arc))
                fh.flush()
                print(f"       -> {arc}")
                time.sleep(d)

    print("\n[5/5]  Archiving finished document ...")
    archive = target / "archive"
    archive.mkdir(exist_ok=True)
    with open(target / "report_draft.txt", "rb") as src, \
            open(archive / "report_draft_v1.txt", "wb") as dst:
        dst.write(src.read())
        dst.flush()
        print("       report_draft.txt  ->  archive/report_draft_v1.txt")
        time.sleep(d)

    print("\n  Goodware worker finished normally.")


if __name__ == "__main__":
    main()
