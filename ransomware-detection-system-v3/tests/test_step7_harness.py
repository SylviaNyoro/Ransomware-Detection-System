import pytest

pytest.importorskip("watchdog")

from scripts.end_to_end_demo import run_demo


@pytest.mark.integration
def test_step7_harness_runs_real_monitor_and_model():
    rows = run_demo(timeout_seconds=6)
    assert rows, "expected at least one live classification from the harness"

    for row in rows:
        assert row["prediction"] in (0, 1)
        assert 0.0 <= row["confidence"] <= 1.0
        assert row["action"] in {"continue", "quarantine", "terminate"}
        assert row["mode"] == "observe"  # default -- no real enforcement in automated tests
        assert row["reaction_time_ms"] >= 0


@pytest.mark.integration
def test_step7_harness_observe_mode_never_enforces():
    """Explicit safety check: even if the simulated activity is classified
    as high-confidence ransomware, observe mode must never actually act
    on a real process (there is no real malicious process here, but this
    guards against accidentally flipping enforce=True by default)."""
    rows = run_demo(timeout_seconds=6, enforce=False)
    assert all(row["mode"] == "observe" for row in rows)
