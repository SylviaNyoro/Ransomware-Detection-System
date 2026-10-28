# Enterprise Ransomware Detection System

A behavior-based ransomware detection prototype using Random Forest classification, real-time filesystem monitoring, and automated process response.

The system monitors filesystem activity on Kali Linux, extracts seven behavioral features, calculates a ransomware confidence score, and selects an appropriate response. A CustomTkinter dashboard displays detections, process information, response decisions, and system logs.

This project was developed as part of the final-year research project titled *An Enterprise Ransomware Detection System using Random Forest Classification*.

## 1. Main Features

- Real-time filesystem monitoring using Watchdog.
- Process attribution using auditd and psutil, with a short-lived PID cache.
- Seven-feature behavioral extraction using a 10-second rolling monitoring window.
- Ransomware classification using a trained Random Forest model.
- Confidence-based CONTINUE, QUARANTINE, and TERMINATE decisions.
- OBSERVE and ENFORCE response modes.
- Authorized demonstration-process suspension and termination using psutil.
- CustomTkinter dashboard with detection history, process panel, and system logs.
- Security alerts for QUARANTINE and TERMINATE decisions.
- JSON evidence logging and automated regression tests.
- Preliminary detection and response latency measurement.

## 2. Technology Stack

- Operating system: Kali Linux
- Programming language: Python
- Machine learning: Scikit-learn RandomForestClassifier
- Filesystem monitoring: Watchdog
- Process attribution: auditd and psutil
- Process response: psutil
- Graphical interface: CustomTkinter
- Model serialization: Joblib
- Configuration: YAML
- Testing: Pytest

## 3. Dataset and Model

The final model was trained using a RanDS-derived filesystem behavioral dataset.

Dataset composition:

| Class | Records |
|---|---:|
| Benign | 15,000 |
| Ransomware | 35,000 |
| Total | 50,000 |

The dataset was divided into grouped training, validation, and held-out test sets.

| Split | Records |
|---|---:|
| Training | 32,002 |
| Validation | 7,999 |
| Test | 9,999 |

The final model uses a Random Forest classifier with:

- 300 decision trees
- Maximum tree depth of 15
- Minimum leaf size of 2
- Balanced class weights

The classifier averages the predicted class probabilities of its decision trees to calculate the ransomware confidence score.

Final model:

`models/rands_random_forest_filesystem.joblib`

The final deployed model does not use the earlier MLRan/DSTI three-feature model or synthetic training data.

## 4. Behavioral Features

The model uses seven filesystem behavioral features:

| Feature | Description |
|---|---|
| changed_file_count | Number of files affected by observed activity |
| file_access_breadth | Breadth of filesystem access |
| directory_traversal_breadth | Number of distinct directories involved |
| file_creation_count | Number of file creation events |
| file_deletion_count | Number of file deletion events |
| extension_diversity | Diversity of file extensions involved |
| file_activity_total | Total recorded filesystem activity |

The live monitoring pipeline uses the same seven-feature schema expected by the trained classifier.

## 5. Model Evaluation

Final held-out test results:

| Metric | Result |
|---|---:|
| Accuracy | 86.99% |
| Precision | 96.23% |
| Recall | 84.73% |
| F1-score | 90.11% |
| ROC-AUC | 95.86% |
| False Positive Rate | 7.73% |
| False Negative Rate | 15.27% |

Confusion matrix:

| Actual / Predicted | Benign | Ransomware |
|---|---:|---:|
| Benign | 2,768 | 232 |
| Ransomware | 1,069 | 5,930 |

The evaluation used a ransomware classification threshold of 62.5%.

Evaluation command:

```bash
python -m scripts.evaluate_rands_filesystem
```

Saved evaluation metrics:

`results/rands_filesystem/test_metrics.json`

## 6. Real-Time Monitoring

The system monitors filesystem activity using Watchdog and attempts process attribution through auditd and psutil.

The monitoring pipeline:

1. Observes filesystem events.
2. Attributes activity to a process where possible.
3. Aggregates events within a rolling 10-second window.
4. Extracts seven behavioral features.
5. Classifies activity using the Random Forest model.
6. Determines and records the appropriate response.

The monitoring loop polls approximately once per second.

Main components:

- `src/monitor/watcher.py`
- `src/monitor/filesystem_aggregator.py`
- `src/monitor/audit_reader.py`
- `src/live_detection.py`

## 7. Automated Response

The system uses three response bands:

| Confidence score | Response |
|---|---|
| Below 20% | CONTINUE |
| 20% to below 62.5% | QUARANTINE |
| 62.5% and above | TERMINATE |

OBSERVE mode records decisions without enforcing them.

ENFORCE mode permits process suspension or termination only for explicitly authorized harmless demonstration processes.

Response components:

- `src/response/enforcement_controller.py`
- `src/response/demo_executor.py`
- `src/response/demo_authorization.py`

Successful enforcement is recorded using statuses such as `suspended_verified` and `terminated_verified`.

## 8. Dashboard

The CustomTkinter dashboard displays detection history, process information, ransomware confidence scores, behavioral features, system logs, and security alerts.

Start the dashboard:

```bash
python -m src.gui.dashboard
```

Run the backend independently:

```bash
python -m src.gui.backend
```

## 9. Demonstrations

Four controlled demonstrations are available.

### Benign activity

```bash
python -m scripts.demo_launcher benign
```

### Quarantine

```bash
python -m scripts.demo_launcher quarantine
```

### Termination

```bash
python -m scripts.demo_launcher ransomware
```

### File creation and deletion

```bash
python -m scripts.demo_launcher creation_deletion
```

The demonstrations use harmless controlled filesystem activity.

## 10. Evidence and Logging

Detection evidence:

`evidence/detection_decisions.jsonl`

Process-specific evidence:

`evidence/process_<pid>.json`

Evidence includes classification results, confidence scores, response decisions, enforcement status, and behavioral features.

One PID may generate multiple detection events across monitoring windows. Detection-event counts should therefore be distinguished from unique process counts.

## 11. Response Latency

A preliminary TERMINATE latency test produced the following results:

| Metric | Result |
|---|---:|
| PID | 35607 |
| Detection latency | 732.080 ms |
| Enforcement latency | 155.675 ms |
| Total response latency | 887.755 ms |
| Enforcement status | terminated_verified |

The system completed the observed detection-and-response sequence in approximately 0.89 seconds during this controlled demonstration.

The measurement represents one run and does not establish consistent performance or a quantified reduction in reaction time.

Latency evidence:

`results/latency/response_latency.csv`

## 12. Resource Consumption

Preliminary observations:

| Condition | Average CPU | Peak CPU | Memory |
|---|---:|---:|---:|
| Baseline | 3.46% | 6% | Approximately 39 MB |
| Active monitoring | 4.37% | 12% | Approximately 39.76–40.36 MB |

These observations do not constitute comprehensive enterprise performance benchmarks.

## 13. Setup and Execution

Activate the existing virtual environment:

```bash
cd ~/ransomware-detection-system-v3
source /root/venv/bin/activate
```

Install dependencies if necessary:

```bash
pip install -r requirements.txt
```

Start the dashboard:

```bash
python -m src.gui.dashboard
```

## 14. Testing

Run the automated test suite:

```bash
python -m pytest -q
```

The project previously passed 80 automated tests. Tests should be rerun after modifications.

## 15. Limitations

- False positives and missed detections remain possible.
- Process attribution is not guaranteed for every filesystem event.
- Enforcement is restricted to authorized demonstration processes.
- The single latency test does not establish average response performance.
- The number of real files encrypted before containment was not measured.
- The prototype has not been validated for unrestricted enterprise deployment.

## 16. Future Improvements

Future development should prioritize improving classification accuracy, process-attribution reliability, automated response verification, and latency measurement under different workloads.

Additional improvements could include centralized endpoint monitoring, extended resource testing, and enhanced dashboard reporting.

## 17. Project Backup

Create a complete ZIP backup:

```bash
cd /root
zip -r ransomware-detection-system-finalversion-backup.zip ransomware-detection-system-v3/
```

Verify the backup:

```bash
unzip -t /root/ransomware-detection-system-finalversion-backup.zip
```

## 18. Project Scope

This project is an academic ransomware detection and response prototype developed for controlled cybersecurity testing. Its results demonstrate the implemented system's capabilities under the evaluated conditions, not guaranteed protection against real-world ransomware.
