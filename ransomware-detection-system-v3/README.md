# Enterprise Ransomware Detection System

Behavior-based ransomware detection using a Random Forest classifier over
three engineered features (Modification Frequency, Extension Change Rate,
File Access Breadth), with real-time file-system monitoring (Watchdog),
automated response (psutil), and a CustomTkinter dashboard.

Based on the 4th-year proposal: *An Enterprise Ransomware Detection System
using Random Forest Classification*.

## Project structure

```
ransomware-detection-system/
├── config.yaml                  # paths, monitored dirs, model + response thresholds
├── requirements.txt
├── src/
│   ├── feature_engineering/
│   │   ├── features.py          # DONE - shared feature computation (tested)
│   │   ├── mlran_parser.py      # DONE - real MLRan report parser (20 samples, ransomware-only)
│   │   ├── dsti_parser.py       # DONE - fallback source parser (12 samples, balanced)
│   │   ├── sgandurra2016_parser.py  # DONE - 1,524 real samples, balanced, but see signal caveat
│   │   └── build_combined_dataset.py  # DONE - merges MLRan + DSTI into 32-row pilot set
│   ├── model/
│   │   ├── train.py             # DONE - Random Forest training (MLRan+DSTI + SMOTE augmentation)
│   │   ├── evaluate.py          # DONE - Accuracy/Precision/Recall/F1/FPR/FNR
│   │   └── augmentation.py      # DONE - SMOTE/ADASYN training-split augmentation
│   ├── monitor/
│   │   └── watcher.py           # DONE - live Watchdog observer + process attribution
│   ├── response/
│   │   └── responder.py         # TODO Step 5 - Continue/Quarantine/Terminate logic
│   ├── gui/
│   │   └── dashboard.py         # TODO Step 6 - CustomTkinter dashboard
│   └── utils/
│       └── logger.py            # DONE - shared logging
├── scripts/
│   ├── demo_monitor.py          # DONE - manual live-monitor demo (watch a dir, print live features)
│   ├── end_to_end_demo.py       # DONE - Step 7 headless harness (rename-only, no encryption)
│   ├── ransomware_sim_demo.py   # DONE - viva demo: real XOR encryption + rename across 5 dirs
│   └── goodware_demo.py         # DONE - viva demo: normal user activity baseline
├── data/
│   ├── raw/                     # MLRan + DSTI sample reports (test fixtures)
│   └── processed/                # engineered feature_vector CSVs land here
├── models/                      # trained .joblib models
├── logs/                        # runtime + forensic logs
└── tests/
    ├── test_features.py         # DONE
    ├── test_mlran_parser.py     # DONE
    ├── test_dsti_parser.py      # DONE
    ├── test_build_combined_dataset.py  # DONE
    ├── test_watcher.py          # DONE - deterministic unit tests
    └── test_watcher_integration.py  # DONE - real Observer, real filesystem
```

## Setup

Single environment — Python 3.14.7 for everything (backend, GUI, tests,
demo scripts).

```bash
python3.14 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

## Build status

| Step | Component | Status |
|---|---|---|
| 1 | Project scaffolding + environment | **Done** |
| 2 | MLRan feature engineering pipeline | **Done** (works, but see data note below) |
| 2b | Fallback data sources (DSTI, Sgandurra 2016) | **Done** -- see caveat on Sgandurra 2016's signal below |
| 3 | Random Forest training & evaluation | **Done** -- Track 1 only (MLRan + DSTI, 22 samples after dedup), training split augmented via SMOTE |
| 4 | Live Watchdog monitoring pipeline | **Done** -- process attribution resolved, see below |
| 5 | Response layer (psutil) | Ready to build -- trained model now available |
| 6 | CustomTkinter dashboard | Pending Steps 4-5 |
| 7 | End-to-end testing harness | Pending Steps 2-6 |

## Important finding: MLRan raw data availability

While building `mlran_parser.py` against the real MLRan repo
(github.com/faithfulco/mlran), found that **only 20 example raw Cuckoo
reports are currently public** (`4_cuckoo_parser_scripts/json_reports/`),
bundled purely for testing the parser scripts. The repo's own
`5_mlran_dataset/README.md` states: *"The full MLRan dataset, containing
all features, will be released after the paper is accepted for
publication."*

The metadata CSV (`2_collected_samples_metadata/mlran_dataset_metadata.csv`)
lists ~4,880 samples (2,330 ransomware / 2,550 goodware) with a
`sample_type` label column (1 = ransomware, 0 = goodware) -- but raw
per-sample behavioral logs only exist for those 20 bundled reports, and
all 20 happen to be ransomware (no goodware example reports are included).

## Fallback data source investigation

Since self-generating data isn't an option for this project, three real
alternatives were checked (search + actual download/inspection, not just
descriptions):

| Source | Real data checked? | Raw file operations? | Goodware included? | Usable now? |
|---|---|---|---|---|
| **MLRan** (official, proposal's source) | Yes, 20 samples | Yes | No (all 20 are ransomware) | Pipeline-proven, not trainable |
| **DSTI-A20-RW/ransomware-preencryption-detector** (GitHub) | Yes, 12 samples | Yes, already parsed | Yes, 6 samples | Pipeline-proven, not trainable |
| **RansomNet** (Zenodo, Agarwal et al.) | No -- 46.2 GB single archive on a domain outside this environment's network allowlist (zenodo.org) | Likely (raw Cuckoo reports are included per its description, alongside a separate API-calls-only extract) | Yes -- 394 ransomware / 229 malware / 271 goodware | Not verified; would need you to download outside this environment |

`src/feature_engineering/dsti_parser.py` is now implemented and tested
against DSTI's real bundled examples, and
`src/feature_engineering/build_combined_dataset.py` merges MLRan + DSTI
into `data/processed/features_combined.csv` -- **32 real, correctly
labeled samples (26 malicious / 6 benign)**. Running it produces visible
signal (e.g. malicious `modification_frequency` values of 35-109 vs.
0-15 for benign in the DSTI examples), which is reassuring for the
feature design, but 32 samples is far too few and too imbalanced to
train or evaluate a classifier that means anything.

**One caveat on DSTI:** its public examples are labeled general
`malware`, subclass `unspecified` -- not confirmed ransomware. Its own
`generate_datasets.py` script shows the authors *did* collect a
ransomware-specific subclass, but that subset isn't in the public repo.
Treat DSTI's "malicious" label as "malicious, ransomware-unconfirmed"
until/unless that subset is obtained directly.

## Update: found a real, balanced, practically-sized dataset (replaces RansomNet)

RansomNet turned out to be impractical (46 GB single archive, and the
disk-partition work was completed but the download itself wasn't
finishable). The real replacement found and integrated:

**Sgandurra et al. (2016), `rissgrouphub/ransomwaredataset2016`**
(github.com/rissgrouphub/ransomwaredataset2016; paper: arXiv:1609.03020,
"Automated Dynamic Analysis of Ransomware: Benefits, Limitations and use
for Detection"). A real, peer-reviewed, widely-cited academic dataset:

- **1,524 real samples: 582 ransomware (11 families) + 942 goodware** --
  properly balanced, unlike MLRan (20, all ransomware) or DSTI (12,
  general malware).
- **Small and practical**: ~500 KB zipped, ~94 MB extracted CSV. No 46 GB
  download, no separate disk partition needed.
- Real Cuckoo Sandbox dynamic analysis, with a `Label` column (1 =
  ransomware, 0 = goodware) matching this project's existing convention.

`src/feature_engineering/sgandurra2016_parser.py` is implemented and
tested (`tests/test_sgandurra2016_parser.py`). It reconstructs FileEvents
from the dataset's `FILES:WRITTEN` / `FILES:OPENED` / `FILES:DELETED`
columns (each column name encodes one exact file path; a `1` means that
sample touched it) and runs them through the exact same
`compute_features()` as MLRan and DSTI, producing directly comparable
feature rows across all three sources.

### Important finding while integrating it -- read before using this data for training

Running the full 1,524-sample dataset through the pipeline produces a
**counterintuitive result**: goodware shows *higher* average
`modification_frequency` (2.32 vs 0.57) and `file_access_breadth` (4.56
vs 2.24) than ransomware -- the opposite of what the proposal's
detection logic assumes.

Investigated why rather than just reporting the numbers: the dataset's
`FILES:*` columns are not each sample's full raw file-operation log.
They are a **feature-selected subset** -- specific paths the original
2016 study chose as useful ML input features, which turn out to skew
toward paths common across many samples (shared install/temp
directories that many *goodware* installers touch) rather than
ransomware's typically unique or randomized per-run write targets. A
direct check confirms this: several `FILES:WRITTEN` columns are hit by
hundreds of goodware samples and almost zero ransomware samples.

**What this means practically:**
- The pipeline and parser are correct -- this is a genuine property of
  the source data, not a bug.
- Training directly on these 3 aggregate features computed *from this
  particular column-reduced source* risks teaching the classifier an
  inverted, dataset-specific artifact that won't hold on live Watchdog
  data (which sees a complete, unreduced event stream, not a
  pre-selected common-path subset). That's a train/inference mismatch
  worth being explicit about in Ch. 3.7.
- MLRan and DSTI don't have this problem -- both give each sample's full
  raw event list, which is what `compute_features()` was designed to
  consume.

**Recommended path forward, in order:**
1. Use Sgandurra 2016 for scale/class-balance validation of the training
   *pipeline* (does the code run, does it produce sane metrics, is the
   train/test split behaving) -- valuable regardless of the signal issue.
2. For the actual reported detection results, weight MLRan/DSTI's
   raw-log samples more heavily, or treat Sgandurra 2016 features as
   supplementary/exploratory rather than primary evidence.
3. If time allows, it may be worth re-deriving features from Sgandurra's
   data differently -- e.g. training directly on a relevant subset of
   its full ~31,000 binary features (closer to what the original paper
   and its many citing works actually did) as a *separate, explicitly
   offline* comparison model, rather than forcing it through the
   3-feature live-monitoring design. This would be new scope, not
   required for Step 3, but worth flagging as a possible extension if
   your supervisor wants a stronger empirical comparison.
4. Worth noting explicitly in Ch. 3.6/3.7: the 2016 dataset is
   Windows-XP-era and stylistically older than MLRan's (which spans
   more recent years per its metadata) -- a second, independent
   limitation on top of the feature-selection issue above.

## Combined dataset sources today

| Source | Samples | Balance | Raw per-sample log? | Used in final approach? |
|---|---|---|---|---|
| MLRan | 20 (all ransomware) | -- | Yes | **Yes -- ransomware class** |
| DSTI | 12 (6 goodware / 6 malware) | -- | Yes (pre-parsed) | **Yes -- goodware class** |
| Sgandurra 2016 | 1,524 (582/942) | Balanced | No -- feature-selected subset, inverted signal (see below) | No -- explored as a possible "Track 2" benchmark, deliberately dropped. Parser (`sgandurra2016_parser.py`) and tests are kept in the repo since they're real, working, and might be useful later, but nothing in the training/eval pipeline depends on them. |
| RansomNet | -- | -- | Unverified | No -- 46 GB Zenodo archive, impractical to acquire; dead end |

`build_combined_dataset.py` merges MLRan + DSTI (32 rows, 22 after
deduplication) -- this is the **entire training corpus** for the final
approach. See `README.md`'s Ch. 3.6 rewrite (discussed in chat, not
duplicated here) for how this is justified in the actual proposal text:
MLRan's public release has no goodware, so DSTI supplies the benign
class, and the two-source combination is framed as a deliberate design
decision, not an improvised workaround.

## Step 3: training & evaluation -- how it works and what it found

`src/model/train.py`, `src/model/evaluate.py` and `src/model/augmentation.py`
are implemented and tested (`tests/test_train_evaluate.py`,
`tests/test_augmentation.py` -- 10 tests total). Pipeline: build the
combined MLRan+DSTI dataset -> drop exact duplicates (10 of 32 rows are
identical low-activity samples that collapse to the same 3-feature
triple -- a real, expected effect of such a small integer-valued feature
space, not a bug) -> stratified 80/20 train/test split -> **SMOTE
augmentation of the training split only** -> StandardScaler fit on the
augmented train data -> RandomForestClassifier -> persist model + scaler
to `models/`.

### Training-set augmentation (SMOTE/ADASYN)

The real, deduplicated dataset is heavily imbalanced (16 ransomware / 6
goodware). Rather than training on that imbalance directly, the training
split (after the train/test split, never before) is augmented with
SMOTE-generated synthetic rows, interpolated between real goodware
neighbors in feature space. This is a standard, well-established
technique for small/imbalanced tabular data -- distinct from event-level
simulation (generating fake file activity) or GAN-based synthesis (which
needs far more real data than is available here to learn anything
meaningful; with ~5 real goodware training samples, a GAN would simply
memorize noise, so it was ruled out rather than attempted).

Two integrity guarantees, both enforced in code and locked in by tests:
- **The held-out test split is always real, unaugmented data only.**
  Augmentation happens strictly after the train/test split, on the
  training portion alone. `test_augmentation_never_changes_test_set_size`
  proves the test split is byte-identical whether augmentation is on or
  off.
- **`k_neighbors` is capped below the minority class's actual sample
  count automatically.** SMOTE's library default (`k_neighbors=5`) would
  outright error on a training split with only ~5 minority samples;
  `augmentation.py` computes a safe value at runtime rather than leaving
  this as a silent failure mode.

Run it with:

```bash
python -m src.model.train
```

A typical run: the real 17-sample training split (12 ransomware / 5
goodware) is augmented to 24 samples (12/12) before the model is fit.
Toggle this off via `config.yaml -> augmentation.enabled: false` to
compare against the unaugmented baseline -- useful for an ablation
comparison in Ch. 3.7 if you want to report both.

**Feature importances** (all three still contribute after augmentation,
confirming Ch. 3.6's requirement that none of the three chosen features
can be dropped):

| Feature | Importance |
|---|---|
| file_access_breadth | 0.54 |
| modification_frequency | 0.27 |
| extension_change_rate | 0.19 |

**Held-out test metrics** (n=5, real data only -- read the caveat in
`evaluate.py`'s docstring before citing these anywhere): accuracy,
precision, recall and F1 all came out at 1.0 on this run. With a test
set this small, that number will swing a lot between random seeds and
is not a meaningful accuracy claim -- it's a sign the pipeline runs
correctly on real, correctly-labeled data, which is exactly what
Ch. 3.6 says this corpus is for.

## Step 3 -> Step 4 integration: proven end-to-end

`tests/test_end_to_end_classification.py` loads the actual persisted
model + scaler and uses them as the live monitor's classification
callback -- no manual wiring, no separate code path. Simulating
ransomware-like activity (rapid file creation with an unusual extension
across multiple directories) through a real `watchdog.Observer`
produced a live classification of **ransomware, 98.5% confidence**,
using the exact model trained above. This is the concrete proof behind
Ch. 3.6's claim that "the same trained classifier can be embedded
directly in the deployed system without any retraining or schema
mismatch."

## MLRan parser -- how it works

`src/feature_engineering/mlran_parser.py` is implemented (not a stub) and
built directly against MLRan's actual report schema, confirmed against
the real `4_cuckoo_parser_scripts/3_file_operations_parser.py` /
`4_directory_operations_parser.py` and a real sample report:

```
report["behavior"]["summary"] = {
    "file_created":   [...],   # -> FileEvent CREATED
    "file_recreated": [...],   # -> FileEvent CREATED
    "file_written":   [...],   # -> FileEvent MODIFIED
    "file_deleted":   [...],   # -> FileEvent DELETED
    "file_opened":    [...],   # -> FileEvent OPENED
    ...
}
```

Labels come from `mlran_dataset_metadata.csv`'s `sample_type` column,
which already matches the proposal's convention (0 = benign, 1 =
ransomware). Run it with:

```bash
python -m src.feature_engineering.mlran_parser
```

which reads `config.yaml -> paths.raw_mlran_dir` and writes
`data/processed/features.csv`. On the 20 bundled samples today, this
produces 20 rows (all label=1) -- correct behavior, just not enough
data yet.

## DSTI parser -- how it works

`src/feature_engineering/dsti_parser.py` reads DSTI's already-parsed
per-sample JSON (`file_operations.files_values` + `file_class.class_label`)
directly -- no raw Cuckoo report parsing needed for this source. Run it
with:

```bash
python -m src.feature_engineering.dsti_parser
```

## Combined pilot dataset

```bash
python -m src.feature_engineering.build_combined_dataset
```

writes `data/processed/features_combined.csv` (32 rows today). Use this
to sanity-check the Step 3 training code once it exists -- not to draw
conclusions about detection performance.

## Step 4: live Watchdog monitor -- how it works

`src/monitor/watcher.py` is fully implemented and tested (unit tests with
no real filesystem, plus a real integration test that runs an actual
`watchdog.Observer` against a real temp directory). Three pieces:

- **`ProcessAttributor`** -- resolves the process-attribution question
  flagged in Step 1. Watchdog reports *what* file changed, not *which
  process* changed it. This periodically snapshots every running
  process's open file handles via `psutil` and matches by path.
  **Known, documented limitation**: it only catches a process while the
  file handle is still open, so a fast open-write-close (which the
  integration test's own file writes demonstrate -- they get `pid=-1`,
  "unknown") is missed. The technically correct fix needs elevated
  privileges (Linux `fanotify` with `FAN_REPORT_PID`, or Windows ETW,
  the mechanism Sysmon/Cuckoo's own agent use) -- documented as a real
  follow-up rather than silently assumed away. Unattributed events are
  still tracked under a shared "unknown" pseudo-PID, not dropped, so no
  signal is silently lost.
- **`LiveAggregator`** -- keeps a rolling per-process window of
  `FileEvent`s and computes a `FeatureVector` on demand using the exact
  same `compute_features()` the offline MLRan/DSTI pipelines use, so
  training-time and inference-time features are guaranteed consistent.
- **`start_monitor()`** -- wires a real `watchdog.Observer` to the above
  and polls for feature vectors on a background thread, calling a
  pluggable `on_features(pid, feature_vector)` callback. Defaults to
  logging when no callback is given, so the monitor runs standalone with
  no dependency on a trained model -- Step 5 will pass a real
  classification callback here instead.

Try it yourself:

```bash
python -m scripts.demo_monitor
# in another terminal:
mkdir -p data/decoy && touch data/decoy/test.txt
mv data/decoy/test.txt data/decoy/test.locked
```


## Step 5: Response layer

`src/response/responder.py` implements the confidence-band decision
logic (Ch. 4.6):

- `< 0.50` -> Continue (log only)
- `0.50-0.79` -> Quarantine (suspend the process via psutil)
- `>= 0.80` -> Terminate (terminate the process via psutil)

`act_on_classification()` is the single entry point: it validates the
thresholds, picks the action, and -- if `enforce=True` -- actually calls
`_quarantine_process()`/`_terminate_process()`. Reaction time is
measured inline and every decision is logged.

**Safety:** the response mode is controlled by `config.yaml ->
response.mode` (`observe` or `enforce`), read by
`src/live_detection.py`'s `create_live_detector()`. In `observe` mode
(the default), the system still classifies and logs the decision but
never actually suspends or terminates a process -- `enforce=False` is
passed straight through to `act_on_classification()`. Only switch to
`enforce` mode for a controlled, deliberate VM demonstration against a
process you've set up specifically to be acted on.

`src/live_detection.py`'s `LiveDetector` ties the trained model
(`src/model/predictor.py`'s `RansomwarePredictor`) and the response
layer together: `on_features(pid, feature_vector)` classifies, decides,
optionally acts, and returns a result dict (`pid`, `prediction`,
`confidence`, `action`, `mode`). This is the same object both
`src/gui/backend.py` (the real GUI backend) and
`scripts/end_to_end_demo.py` (the Step 7 harness) use -- one
implementation of the classify-then-respond path, not two.

Run the policy tests:

```bash
pytest tests/test_responder.py -v
```

## Step 6: Dashboard

Everything runs in a single Python 3.14.7 venv. The dashboard and
detection backend still run as **two separate processes communicating
over JSON Lines through stdout**, but both processes now use the same
interpreter via `sys.executable` — no second venv or separate Python
version needed:

- `src/gui/backend.py` builds a `LiveDetector`, starts the real Watchdog
  monitor, and for every classification prints one JSON line
  (`{"type": "detection", "data": {...}}`) to stdout.
- `src/gui/dashboard.py` spawns `backend.py` as a subprocess when you
  click "Start Monitoring" using `sys.executable` (the same Python
  running the dashboard), reads its stdout line by line on a background
  thread, and renders each `detection` message: monitoring status, live
  threat/action counters, latest prediction/confidence/action, the
  current three-feature vector, a scrollable detection history (latest
  100), and a scrolling system log.
- `src/gui/dashboard_state.py`'s `DashboardState` holds all of the
  counter/history/log bookkeeping, with **no CustomTkinter or tkinter
  import at all** — `DashboardApp` calls
  `self.state.record_detection(data)` once per message and then just
  renders whatever `self.state` now holds. This is what makes the
  dashboard's logic unit-testable without a display.

Run the GUI (activate the main venv first):

```bash
source venv/bin/activate
python -m src.gui.dashboard
```

Click "Start Monitoring", then create/modify/rename files under the
configured decoy directory (`config.yaml -> monitor.watched_directories`).
The dashboard updates live as the backend subprocess emits detections.

You can also run the backend alone, headless, without any GUI
environment at all -- useful for confirming the detection pipeline works
before touching the GUI:

```bash
python -m src.gui.backend
```

## Step 7: Testing harness

`tests/test_responder.py` verifies the confidence bands, threshold
validation, observe-mode safety (no process action taken), and
enforce-mode behavior (the right psutil call is made).

`tests/test_dashboard.py` verifies `DashboardState` directly: counters,
history capping, last-detection tracking, and reaction-time averaging --
all without importing `dashboard.py` itself, so these tests don't need
tkinter or customtkinter installed at all.

`scripts/end_to_end_demo.py` is a safe, headless end-to-end harness. It:

1. creates a temporary directory (never touches `data/decoy`);
2. builds a real `LiveDetector` from the persisted model + scaler via
   `create_live_detector()`;
3. starts the real Watchdog observer;
4. performs ransomware-like *filesystem activity only* -- plain file
   create/rename calls, no ransomware or malicious code anywhere;
5. runs the actual classifier and response decision through
   `LiveDetector.on_features()`, in `observe` mode by default
   (`enforce=False` unless explicitly requested);
6. measures reaction time per classification.

Deliberately has no dependency on `src/gui/dashboard.py` or
`src/gui/backend.py` -- the harness needs to keep running in the plain
backend environment even if the separate GUI environment isn't set up.

Run it with:

```bash
python -m scripts.end_to_end_demo
pytest tests/test_step7_harness.py -v
```

The harness deliberately does not execute malware. It tests the
detection and response pipeline using controlled file activity only.

## Viva live-demo scripts

Two scripts produce a real, screen-recordable classification contrast for
the viva — implementing the approach stated in proposal Ch. 3.6:
*"ransomware-like activities (carried out with the help of a controlled
encryption script)."*

### `scripts/ransomware_sim_demo.py` — controlled encryption simulation

Creates 15 throwaway decoy files across 5 sub-directories, **encrypts
their content in-place** with a single-byte XOR cipher (key printed
before any file is touched, so every file is trivially recoverable),
then renames each to a ransomware-typical extension (`.locked` / `.enc`).

This produces all three feature signals the model looks for:

| Feature | Value | Why |
|---|---|---|
| `modification_frequency` | high (~30) | one CREATE + one MODIFIED per file |
| `extension_change_rate` | 2 | `.locked` and `.enc` are both unusual |
| `file_access_breadth` | 5 | spread across docs / finance / hr / projects / admin |

**Scope limits** (why this cannot cause harm):
- Every file it touches is one it created itself, inside a throwaway temp dir.
- The XOR key is printed to stdout before any operation; decryption is
  `bytes(b ^ key for b in file.read_bytes())`.
- No network calls, no persistence, no spreading.

```bash
# headless — uses a system temp dir, cleaned up on exit
python -m scripts.ransomware_sim_demo

# --live — writes to data/decoy/sim_ransomware so the GUI backend also sees it
python -m scripts.ransomware_sim_demo --live
```

### `scripts/goodware_demo.py` — normal-user-activity simulation

Simulates a user editing a document, appending to a log file, and
extracting a small zip attachment.  All operations use common extensions
(`.txt`, `.csv`, `.log`) and stay in one or two directories.

| Feature | Value | Why |
|---|---|---|
| `modification_frequency` | low (~8) | a handful of writes |
| `extension_change_rate` | 0 | every extension is in `common_extensions` |
| `file_access_breadth` | 2 | root dir + one sub-folder |

Expected result: no detection fires, or a very low-confidence "continue"
classification.  Either outcome is correct for benign activity.

```bash
python -m scripts.goodware_demo        # headless
python -m scripts.goodware_demo --live # GUI-visible
```

### Suggested viva screen-recording workflow

**Headless (terminal only):**
```bash
# Terminal 1 — run goodware first to establish baseline
python -m scripts.goodware_demo

# Terminal 1 — then run the ransomware sim to show the contrast
python -m scripts.ransomware_sim_demo
```

**With the GUI dashboard (Step 6 environment):**
```bash
# Terminal 1 — start the dashboard
python -m src.gui.dashboard

# Terminal 2 — goodware: dashboard should stay green / "continue"
python -m scripts.goodware_demo --live

# Terminal 2 — ransomware sim: dashboard should fire quarantine/terminate
python -m scripts.ransomware_sim_demo --live
```

Both scripts use the same `create_live_detector()` and `start_monitor()`
entry points as the GUI backend and the Step 7 harness, so the
classification shown is genuine — the same model, the same feature
pipeline, the same response layer.

## Current verification

44 tests pass in this environment (`pytest tests/ -v`), covering feature
engineering, all three data-source parsers, training/evaluation/
augmentation, the live Watchdog monitor (including a real
`watchdog.Observer` integration test), the response layer, `DashboardState`,
and the Step 7 end-to-end harness (a real classification through a real
monitor, real model, and real response decision).

`tests/test_dashboard.py` has no customtkinter import and runs fine with
`pytest tests/ -v` in the main venv. Actually opening and visually
exercising `DashboardApp` itself requires a display — that part isn't
automated here, and should be checked manually (`python -m src.gui.dashboard`).

