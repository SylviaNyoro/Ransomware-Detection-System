"""Process identity verification for controlled demonstrations."""

import json
from pathlib import Path

import psutil


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTH_DIR = PROJECT_ROOT / "data" / "demo_authorization"

ALLOWED_DEMOS = {
    "benign": "benign.sh",
    "quarantine": "quarantine.sh",
    "ransomware": "ransomware_classification_demo.py",
    "creation_deletion": "test_creation_deletion.py",
}


def is_authorized_demo(pid: int | None) -> bool:
    """Verify an active process against its launcher registration."""
    if not isinstance(pid, int) or pid <= 1:
        return False

    path = AUTH_DIR / f"{pid}.json"

    try:
        identity = json.loads(path.read_text(encoding="utf-8"))
        process = psutil.Process(pid)

        demo = identity.get("demo")

        if demo not in ALLOWED_DEMOS:
            return False

        if identity.get("pid") != pid:
            return False

        if abs(
            process.create_time()
            - float(identity["create_time"])
        ) >= 0.001:
            return False

        if not process.is_running():
            return False

        if process.status() == psutil.STATUS_ZOMBIE:
            return False

        command = process.cmdline()
        expected_script = ALLOWED_DEMOS[demo]

        # Shell demos execute Python from standard input.
        if demo in {"benign", "quarantine"}:
            return (
                len(command) >= 2
                and Path(command[0]).name.startswith("python")
                and command[1] == "-"
            )

        # Python demos execute a named script.
        return any(
            Path(argument).name == expected_script
            for argument in command[1:]
        )

    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        psutil.Error,
    ):
        return False
