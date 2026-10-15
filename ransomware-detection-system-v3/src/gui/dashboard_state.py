"""
Framework-independent state tracking for the dashboard (Ch. 4, GUI).

Deliberately has NO dependency on tkinter or customtkinter, so it can be
unit-tested in the plain Python 3.12 backend environment without needing
the separate Python 3.14 GUI environment at all (see README.md's Step 6
for why the GUI needs a separate environment). DashboardApp
(dashboard.py) owns one DashboardState instance and updates its
CustomTkinter widgets FROM it, rather than tracking counters/history/
logs directly inside widget-coupled code.

This mirrors the single "detection" message type the real backend
(src/gui/backend.py) actually sends -- one combined message per
classification, carrying prediction, confidence, action, pid and
features together -- rather than separate messages per concern.
"""

from datetime import datetime


class DashboardState:
    """Tracks detection counters, session history, and log lines from
    backend 'detection' messages, independent of any GUI framework."""

    def __init__(self, history_limit: int = 100):
        self.history_limit = history_limit
        self.counters = {
            "total": 0,
            "ransomware": 0,
            "goodware": 0,
            "continue": 0,
            "quarantine": 0,
            "terminate": 0,
        }
        self.history: list[dict] = []
        self.logs: list[str] = []
        self.last_prediction = None
        self.last_confidence = 0.0
        self.last_pid = None
        self.last_action = None
        self.last_features: dict = {}
        self._reaction_times: list[float] = []

    def record_detection(self, data: dict) -> str:
        """Update counters/history/logs from one backend 'detection'
        message (see src/gui/backend.py's send_message schema). Returns
        the formatted log line, so DashboardApp can push it into the
        Tkinter log box without duplicating the formatting logic."""
        prediction = data.get("prediction")
        confidence = float(data.get("confidence", 0.0))
        action = str(data.get("action", "unknown")).lower()
        pid = data.get("pid")
        features = data.get("features", {})
        reaction_time_ms = data.get("reaction_time_ms")

        self.last_prediction = prediction
        self.last_confidence = confidence
        self.last_pid = pid
        self.last_action = action
        self.last_features = features

        self.counters["total"] += 1
        self.counters["ransomware" if prediction == 1 else "goodware"] += 1
        if action in self.counters:
            self.counters[action] += 1

        if reaction_time_ms is not None:
            self._reaction_times.append(float(reaction_time_ms))

        timestamp = datetime.now().strftime("%H:%M:%S")
        prediction_text = "RANSOMWARE" if prediction == 1 else "GOODWARE"
        entry = {
            "time": timestamp,
            "pid": pid if pid is not None else "-",
            "prediction": prediction_text,
            "confidence": confidence,
            "action": action.upper(),
        }
        self.history.append(entry)
        if len(self.history) > self.history_limit:
            self.history = self.history[-self.history_limit:]

        log_line = (
            f"PID={pid} | prediction={prediction_text} | "
            f"confidence={confidence * 100:.2f}% | action={action.upper()}"
        )
        self.logs.append(log_line)
        return log_line

    def reset_counters(self):
        for key in self.counters:
            self.counters[key] = 0

    @property
    def classifications(self) -> int:
        return self.counters["total"]

    @property
    def threats(self) -> int:
        return self.counters["ransomware"]

    @property
    def average_reaction_ms(self) -> float:
        if not self._reaction_times:
            return 0.0
        return sum(self._reaction_times) / len(self._reaction_times)
