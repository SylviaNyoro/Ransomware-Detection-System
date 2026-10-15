"""
End-to-end proof that the trained model (Step 3) plugs directly into the
live monitor (Step 4) with no retraining or schema mismatch -- exactly
the claim Ch. 3.6/3.7 make about train/deployment feature consistency.

Loads the persisted model + scaler and uses them as the on_features
callback for start_monitor(), classifying real live file activity as it
happens. This is what Step 5 (response layer) will build on -- this test
only proves classification works live, not the Continue/Quarantine/
Terminate action logic, which is still a TODO in responder.py.
"""

import time

import pytest
pytest.importorskip("watchdog")

import joblib
import pandas as pd
import yaml

from src.model.train import FEATURE_COLUMNS
from src.monitor.watcher import start_monitor


def test_trained_model_classifies_live_feature_vectors(tmp_path):
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    model = joblib.load(cfg["paths"]["model_path"])
    scaler = joblib.load(cfg["paths"]["model_path"].replace(".joblib", "_scaler.joblib"))

    classifications = []

    def on_features(pid, fv):
        row = pd.DataFrame([fv.as_dict()])[FEATURE_COLUMNS]
        scaled = scaler.transform(row)
        prediction = model.predict(scaled)[0]
        confidence = model.predict_proba(scaled)[0][prediction]
        classifications.append((pid, fv, int(prediction), float(confidence)))

    observer, stop_event = start_monitor(
        watched_directories=[str(tmp_path)],
        common_extensions=cfg["features"]["common_extensions"],
        poll_interval_seconds=0.2,
        window_seconds=5,
        on_features=on_features,
    )

    try:
        # Ransomware-like: rapid creation + rename to an unusual extension
        # across multiple subdirectories.
        for i, subdir in enumerate(["a", "b", "c"]):
            d = tmp_path / subdir
            d.mkdir()
            f = d / f"doc{i}.txt"
            f.write_text("data")
            f.rename(d / f"doc{i}.encrypted")

        deadline = time.time() + 5
        while time.time() < deadline and not classifications:
            time.sleep(0.2)
    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=5)

    assert classifications, "expected at least one live classification"
    for pid, fv, prediction, confidence in classifications:
        assert prediction in (0, 1)
        assert 0.0 <= confidence <= 1.0
    print("\nLive classifications:", classifications)
