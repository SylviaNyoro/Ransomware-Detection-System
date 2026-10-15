"""
Enterprise Ransomware Detection System Dashboard.

Runs with Python 3.14.7 and CustomTkinter in the same venv as the
detection backend.  The dashboard spawns backend.py as a subprocess
(using sys.executable so both share the same interpreter) and
communicates with it over JSON Lines on stdout.

Dashboard additions:
    - live threat/action counters
    - persistent detection history for the current dashboard session
    - latest detection details
    - live behavioral feature values
    - scrolling system log
"""

import json
import os
import subprocess
import sys
import threading
import tkinter.messagebox as messagebox

import customtkinter as ctk

from src.gui.dashboard_state import DashboardState


PROJECT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

# Use the same Python interpreter that is running this dashboard, so
# the backend subprocess shares the same venv without any hardcoded path.
BACKEND_PYTHON = sys.executable
BACKEND_SCRIPT = os.path.join(
    PROJECT_DIR,
    "src",
    "gui",
    "backend.py",
)


class DashboardApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Enterprise Ransomware Detection System")
        # Extra vertical space keeps all three behavioral feature rows visible.
        self.geometry("1250x1050")
        self.minsize(1050, 950)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.backend_process = None
        self.reader_thread = None
        self.monitoring = False
        self.current_mode = "observe"

        self.app_state = DashboardState()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.build_interface()

        self.log_message("Dashboard initialized.")
        self.log_message("Detection backend is ready.")

    # -----------------------------------------------------------------
    # Interface
    # -----------------------------------------------------------------

    def build_interface(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # Header
        header = ctk.CTkFrame(self, corner_radius=12)
        header.grid(row=0, column=0, padx=20, pady=(20, 8), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Enterprise Ransomware Detection System",
            font=ctk.CTkFont(size=25, weight="bold"),
        ).grid(row=0, column=0, padx=20, pady=(14, 2), sticky="w")

        ctk.CTkLabel(
            header,
            text="Real-time behavioral ransomware detection",
            font=ctk.CTkFont(size=14),
        ).grid(row=1, column=0, padx=20, pady=(0, 14), sticky="w")

        # Monitoring status
        status_frame = ctk.CTkFrame(self, corner_radius=12)
        status_frame.grid(row=1, column=0, padx=20, pady=8, sticky="ew")
        status_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            status_frame,
            text="MONITORING STATUS",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, padx=(20, 10), pady=13)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="● STOPPED",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.status_label.grid(row=0, column=1, padx=10, pady=13, sticky="w")

        self.mode_label = ctk.CTkLabel(
            status_frame,
            text="Mode: OBSERVE",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.mode_label.grid(row=0, column=2, padx=15, pady=13)

        self.start_button = ctk.CTkButton(
            status_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            width=155,
        )
        self.start_button.grid(row=0, column=3, padx=(8, 8), pady=13)

        self.stop_button = ctk.CTkButton(
            status_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            width=155,
            state="disabled",
        )
        self.stop_button.grid(row=0, column=4, padx=(0, 20), pady=13)

        # Counters
        counters_frame = ctk.CTkFrame(self, corner_radius=12)
        counters_frame.grid(row=2, column=0, padx=20, pady=8, sticky="ew")

        for column in range(6):
            counters_frame.grid_columnconfigure(column, weight=1)

        counter_specs = [
            ("total", "TOTAL DETECTIONS"),
            ("ransomware", "RANSOMWARE"),
            ("goodware", "GOODWARE"),
            ("continue", "CONTINUE"),
            ("quarantine", "QUARANTINE"),
            ("terminate", "TERMINATE"),
        ]

        self.counter_labels = {}

        for column, (key, title) in enumerate(counter_specs):
            card = ctk.CTkFrame(counters_frame, corner_radius=10)
            card.grid(
                row=0,
                column=column,
                padx=5,
                pady=8,
                sticky="nsew",
            )

            ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(size=10, weight="bold"),
            ).pack(pady=(10, 2))

            value = ctk.CTkLabel(
                card,
                text="0",
                font=ctk.CTkFont(size=24, weight="bold"),
            )
            value.pack(pady=(0, 10))
            self.counter_labels[key] = value

        # Main content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=3, column=0, padx=20, pady=8, sticky="ew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)

        # Latest detection
        result_frame = ctk.CTkFrame(content, corner_radius=12)
        result_frame.grid(row=0, column=0, padx=(0, 8), sticky="nsew")

        ctk.CTkLabel(
            result_frame,
            text="Latest Detection",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.prediction_label = ctk.CTkLabel(
            result_frame,
            text="No prediction yet",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        self.prediction_label.pack(pady=3)

        self.confidence_label = ctk.CTkLabel(
            result_frame,
            text="Confidence: --",
            font=ctk.CTkFont(size=16),
        )
        self.confidence_label.pack(pady=3)

        self.action_label = ctk.CTkLabel(
            result_frame,
            text="Action: --",
            font=ctk.CTkFont(size=19, weight="bold"),
        )
        self.action_label.pack(pady=(3, 12))

        # Process information
        process_frame = ctk.CTkFrame(content, corner_radius=12)
        process_frame.grid(row=0, column=1, padx=(8, 0), sticky="nsew")

        ctk.CTkLabel(
            process_frame,
            text="Process Information",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.pid_label = ctk.CTkLabel(
            process_frame, text="PID: --", font=ctk.CTkFont(size=15)
        )
        self.pid_label.pack(anchor="w", padx=20, pady=3)

        self.directory_label = ctk.CTkLabel(
            process_frame,
            text="Watched directory: data/decoy",
            font=ctk.CTkFont(size=15),
        )
        self.directory_label.pack(anchor="w", padx=20, pady=3)

        self.mode_detail_label = ctk.CTkLabel(
            process_frame,
            text="Response mode: observe",
            font=ctk.CTkFont(size=15),
        )
        self.mode_detail_label.pack(anchor="w", padx=20, pady=3)

        self.threshold_label = ctk.CTkLabel(
            process_frame,
            text="Thresholds: --",
            font=ctk.CTkFont(size=14),
        )
        self.threshold_label.pack(anchor="w", padx=20, pady=(3, 12))

        # Lower content area
        lower = ctk.CTkFrame(self, fg_color="transparent")
        lower.grid(row=4, column=0, padx=20, pady=8, sticky="nsew")
        lower.grid_columnconfigure(0, weight=1)
        lower.grid_columnconfigure(1, weight=1)
        # Reserve enough height for the feature panel and its three rows,
        # while keeping the detection history comfortably visible.
        lower.grid_rowconfigure(0, weight=3, minsize=205)
        lower.grid_rowconfigure(1, weight=2, minsize=180)

        # Behavioral features
        features_frame = ctk.CTkFrame(lower, corner_radius=12)
        features_frame.grid(row=0, column=0, padx=(0, 8), pady=(0, 8), sticky="nsew")
        features_frame.grid_columnconfigure(1, weight=1)
        features_frame.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(
            features_frame,
            text="Behavioral Features",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).grid(row=0, column=0, columnspan=2, padx=20, pady=(14, 10), sticky="w")

        self.modification_label = self.add_feature_row(
            features_frame, 1, "Modification Frequency"
        )
        self.extension_label = self.add_feature_row(
            features_frame, 2, "Extension Change Rate"
        )
        self.breadth_label = self.add_feature_row(
            features_frame, 3, "File Access Breadth"
        )

        # System log
        log_frame = ctk.CTkFrame(lower, corner_radius=12)
        log_frame.grid(row=0, column=1, padx=(8, 0), pady=(0, 8), sticky="nsew")

        ctk.CTkLabel(
            log_frame,
            text="System Log",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.log_box = ctk.CTkTextbox(log_frame, wrap="word", font=ctk.CTkFont(size=13))
        self.log_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.log_box.configure(state="disabled")

        # Detection history
        history_frame = ctk.CTkFrame(lower, corner_radius=12)
        history_frame.grid(row=1, column=0, columnspan=2, pady=(8, 0), sticky="nsew")
        history_frame.grid_rowconfigure(1, weight=1)
        history_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            history_frame,
            text="Detection History",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).grid(row=0, column=0, padx=20, pady=(12, 7), sticky="w")

        self.history_scroll = ctk.CTkScrollableFrame(
            history_frame,
            height=110,
            corner_radius=8,
        )
        self.history_scroll.grid(
            row=1,
            column=0,
            padx=12,
            pady=(0, 12),
            sticky="nsew",
        )
        self.history_scroll.grid_columnconfigure(0, weight=1)

        # Footer
        ctk.CTkLabel(
            self,
            text="Random Forest behavioral detection | 10-second rolling observation window",
            font=ctk.CTkFont(size=11),
        ).grid(row=5, column=0, padx=20, pady=(3, 12))

    # -----------------------------------------------------------------
    # Feature row
    # -----------------------------------------------------------------

    def add_feature_row(self, parent, row, name):
        ctk.CTkLabel(
            parent,
            text=name,
            font=ctk.CTkFont(size=14),
        ).grid(row=row, column=0, padx=20, pady=8, sticky="w")

        value_label = ctk.CTkLabel(
            parent,
            text="0",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        value_label.grid(row=row, column=1, padx=20, pady=8, sticky="e")
        return value_label

    # -----------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------

    def log_message(self, message):
        tag = "normal"
        if any(x in message for x in ["TERMINAT", "⛔"]):
            tag = "threat"
        elif any(x in message for x in ["QUARANTIN", "⚠"]):
            tag = "warn"
        elif any(x in message for x in ["CONTINUE", "✓", "GOODWARE", "goodware"]):
            tag = "safe"
        elif "RANSOMWARE" in message:
            tag = "threat"
        tb = self.log_box._textbox
        tb.configure(state="normal")
        tb.tag_configure("threat", foreground="#ff4444")
        tb.tag_configure("warn",   foreground="#ffaa00")
        tb.tag_configure("safe",   foreground="#44cc44")
        tb.tag_configure("normal", foreground="gray80")
        tb.insert("end", message + "\n", tag)
        tb.see("end")
        tb.configure(state="disabled")

    # -----------------------------------------------------------------
    # Counters and history
    # -----------------------------------------------------------------

    def update_counter_labels(self):
        """Refresh every counter widget from self.app_state.counters."""
        for key, label in self.counter_labels.items():
            label.configure(text=str(self.app_state.counters.get(key, 0)))

    def reset_counters(self):
        self.app_state.reset_counters()
        self.update_counter_labels()

    def refresh_history(self):
        for widget in self.history_scroll.winfo_children():
            widget.destroy()

        headers = ["Time", "PID", "Prediction", "Confidence", "Action"]
        widths = [100, 100, 180, 140, 150]

        for column, (header, width) in enumerate(zip(headers, widths)):
            ctk.CTkLabel(
                self.history_scroll,
                text=header,
                width=width,
                font=ctk.CTkFont(size=11, weight="bold"),
            ).grid(row=0, column=column, padx=4, pady=(2, 6), sticky="w")

        # Newest detection appears first.
        for row, entry in enumerate(reversed(self.app_state.history), start=1):
            values = [
                entry["time"],
                str(entry["pid"]),
                entry["prediction"],
                f'{entry["confidence"] * 100:.2f}%',
                entry["action"],
            ]

            for column, (value, width) in enumerate(zip(values, widths)):
                ctk.CTkLabel(
                    self.history_scroll,
                    text=value,
                    width=width,
                    font=ctk.CTkFont(size=11),
                ).grid(row=row, column=column, padx=4, pady=3, sticky="w")

    # -----------------------------------------------------------------
    # Start backend
    # -----------------------------------------------------------------

    def start_monitoring(self):
        if self.backend_process is not None:
            return

        self.log_message("Starting detection backend...")

        try:
            self.backend_process = subprocess.Popen(
                [BACKEND_PYTHON, BACKEND_SCRIPT],
                cwd=PROJECT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.backend_process = None
            messagebox.showerror("Backend Error", str(exc))
            return

        self.monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_label.configure(text="● STARTING")

        self.reader_thread = threading.Thread(
            target=self.read_backend_output,
            daemon=True,
        )
        self.reader_thread.start()

        self.log_message("Detection backend launched.")

    # -----------------------------------------------------------------
    # Read backend
    # -----------------------------------------------------------------

    def read_backend_output(self):
        process = self.backend_process
        if process is None:
            return

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    self.after(0, self.log_message, line)
                    continue

                self.after(0, self.process_backend_message, message)

        except Exception as exc:
            self.after(0, self.log_message, f"Backend reader error: {exc}")
        finally:
            self.after(0, self.backend_finished)

    # -----------------------------------------------------------------
    # Backend messages
    # -----------------------------------------------------------------

    def process_backend_message(self, message):
        message_type = message.get("type")

        if message_type == "status":
            self.handle_status(message)
        elif message_type == "detection":
            self.handle_detection(message.get("data", {}))
        elif message_type == "log":
            self.log_message(message.get("message", ""))
        elif message_type == "error":
            self.log_message(
                f"ERROR: {message.get('message', 'Unknown backend error')}"
            )

    # -----------------------------------------------------------------
    # Status
    # -----------------------------------------------------------------

    def handle_status(self, message):
        status = message.get("status", "")

        if status == "starting":
            self.status_label.configure(text="● STARTING")
            self.log_message(message.get("message", "Starting..."))

        elif status == "running":
            self.status_label.configure(text="● RUNNING")
            self.monitoring = True

            mode = message.get("mode", "observe")
            self.current_mode = mode
            self.mode_label.configure(text=f"Mode: {mode.upper()}")
            self.mode_detail_label.configure(text=f"Response mode: {mode}")

            directories = message.get("directories", [])
            if directories:
                self.directory_label.configure(
                    text="Watched directory: " + ", ".join(directories)
                )

            quarantine = message.get("quarantine_threshold")
            terminate = message.get("terminate_threshold")
            if quarantine is not None and terminate is not None:
                self.threshold_label.configure(
                    text=(
                        f"Thresholds: Quarantine {quarantine * 100:.0f}% | "
                        f"Terminate {terminate * 100:.0f}%"
                    )
                )

            self.log_message(
                message.get("message", "Monitoring active.")
            )

        elif status == "stopped":
            self.status_label.configure(text="● STOPPED")
            self.log_message(message.get("message", "Backend stopped."))

    # -----------------------------------------------------------------
    # Detection result
    # -----------------------------------------------------------------

    def handle_detection(self, data):
        prediction = data.get("prediction")
        confidence = float(data.get("confidence", 0.0))
        action = data.get("action", "unknown")
        pid = data.get("pid")
        mode = data.get("mode", self.current_mode)
        features = data.get("features", {})

        # Delegate all counter/history/log bookkeeping to the
        # framework-independent DashboardState, then just render it.
        log_line = self.app_state.record_detection(data)

        prediction_text = "RANSOMWARE" if prediction == 1 else "GOODWARE"

        self.prediction_label.configure(text=prediction_text)
        self.confidence_label.configure(
            text=f"Confidence: {confidence * 100:.2f}%"
        )
        self.action_label.configure(text=f"Action: {str(action).upper()}")

        self.pid_label.configure(
            text="PID: Unknown" if pid == -1 else f"PID: {pid}"
        )

        self.mode_detail_label.configure(text=f"Response mode: {mode}")
        self.mode_label.configure(text=f"Mode: {mode.upper()}")

        # Read the three shared feature names emitted by the live backend.
        # Use an em dash if a field was not supplied instead of implying it is 0.
        self.modification_label.configure(
            text=self.format_feature(features, "modification_frequency")
        )
        self.extension_label.configure(
            text=self.format_feature(features, "extension_change_rate")
        )
        self.breadth_label.configure(
            text=self.format_feature(features, "file_access_breadth")
        )

        self.update_counter_labels()
        self.refresh_history()
        self.log_message(log_line)

    @staticmethod
    def format_feature(features, key):
        """Format a feature value, distinguishing missing data from zero."""
        value = features.get(key)
        if value is None:
            return "—"
        if isinstance(value, float):
            return f"{value:.3f}".rstrip("0").rstrip(".")
        return str(value)

    # -----------------------------------------------------------------
    # Stop backend
    # -----------------------------------------------------------------

    def stop_monitoring(self):
        process = self.backend_process
        if process is None:
            return

        self.log_message("Stopping detection backend...")

        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as exc:
            self.log_message(f"Error stopping backend: {exc}")

        self.backend_process = None
        self.monitoring = False
        self.status_label.configure(text="● STOPPED")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.log_message("Detection backend stopped.")

    # -----------------------------------------------------------------
    # Backend finished
    # -----------------------------------------------------------------

    def backend_finished(self):
        if self.backend_process is not None:
            return_code = self.backend_process.poll()

            if return_code is not None:
                self.backend_process = None
                self.monitoring = False
                self.status_label.configure(text="● STOPPED")
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.log_message(
                    f"Detection backend exited (code {return_code})."
                )

    # -----------------------------------------------------------------
    # Close application
    # -----------------------------------------------------------------

    def on_close(self):
        if self.backend_process is not None:
            try:
                self.backend_process.terminate()
                self.backend_process.wait(timeout=3)
            except Exception:
                try:
                    self.backend_process.kill()
                except Exception:
                    pass

        self.destroy()


if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()
