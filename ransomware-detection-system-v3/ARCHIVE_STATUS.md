# Archive status

This ZIP is a consolidated reconstruction of the ransomware-detection-system project using the latest project archive available in the conversation plus the source files/changes supplied in the subsequent implementation steps.

Included updates from the latest implementation work:

- `src/live_detection.py`
- `src/model/predictor.py`
- current `src/gui/dashboard.py`
- JSON-lines `src/gui/backend.py`
- current Watchdog monitor with rolling feature window
- current confidence-based response layer
- current `config.yaml`
- GUI Python 3.14 requirements in `requirements-gui.txt`
- current responder unit tests supplied during implementation
- trained Random Forest model and scaler artifacts from the latest project archive

The working project on Kali was separately verified by the user after these changes with **47 passed** tests. The ZIP was reconstructed outside that Kali filesystem, so the exact live 47-test source tree could not be copied byte-for-byte; the archive contains the recoverable project source and test files from the available project archive and conversation materials.

## Update: inconsistencies found and fixed after reconstruction

As anticipated by this file's own caveat above (byte-for-byte source
could not be recovered), the reconstruction pulled in two files from an
earlier, abandoned design that never matched the final, working one:

- `scripts/end_to_end_demo.py` and `tests/test_step7_harness.py`
  referenced `ResponseExecutor`/`ResponseManager` (responder.py) and
  `DashboardEventBus`/`DashboardState` (dashboard.py) -- none of which
  exist in the actual, current, working `responder.py`/`dashboard.py`.
  Both files have been rewritten to use the real current architecture
  (`LiveDetector` from `src/live_detection.py`, no GUI dependency at all
  for the harness, since Step 7 shouldn't need a GUI).
- `tests/test_dashboard.py` had the same problem (tested the abandoned
  `DashboardEventBus`/`DashboardState`). Fixed by extracting a real,
  framework-independent `DashboardState` class
  (`src/gui/dashboard_state.py`, no tkinter/customtkinter import at
  all) out of `DashboardApp`'s previously inline counter/history logic,
  and rewriting the test against that real class.
- `scripts/run_system.py` had the same stale imports AND was
  architecturally incompatible with the real design regardless (it
  tried to run the CustomTkinter dashboard in the same process as the
  Python-3.12-only model/Watchdog code, which can't work given the
  Python 3.12/3.14 environment split this project settled on). Deleted
  rather than patched, since `src/gui/dashboard.py` launching
  `src/gui/backend.py` as a subprocess already is the correct current
  entry point.
- `README.md`'s Step 5/6/7 sections described the same abandoned
  architecture and have been rewritten to match what's actually in the
  codebase and actually passes.
- `config.yaml` was missing an explicit `response.mode` key (code
  defaulted to `"observe"` safely, but the README now tells people to
  toggle it there, so it's now written explicitly).

After these fixes: **44 tests pass** in this environment (`pytest
tests/ -v`), covering feature engineering, all data-source parsers,
training/evaluation/augmentation, the live Watchdog monitor (including a
real `Observer` integration test), the response layer, `DashboardState`,
and a real end-to-end Step 7 harness run. This is 3 fewer than the 47
reported on the original Kali run -- consistent with this file's own
up-front caveat that exact parity wasn't guaranteed.
