# CS5231 Systems Security Final Project: Traced-based Exploit Detection

This project contains a pipeline that parses log messages, detects known exploitation patterns, builds provenance graphs, and asks OpenAI to generate a concise paragraph for IT security staff summarizing findings.

Features
- Template mining using drain3 to cluster log message templates
- Heuristic exploit detection (SSH brute force, privilege escalation, port scanning, SQL/command injection, buffer overflow, data exfiltration)
- Provenance graph generation (NetworkX + Matplotlib)
- Optional OpenAI integration to produce an actionable paragraph (requires `OPENAI_API_KEY`)

Quick start

1. Create and activate a Python virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies

Recommended: install from the pinned `requirements.txt` included in this repository. This ensures a compatible set of packages.

```bash
pip install -r requirements.txt
```

3. Set your OpenAI API key (optional, for LLM paragraph generation):

```bash
export OPENAI_API_KEY="sk-..."
```

4. Run the pipeline using sample logs (or pass a JSON file):

```bash
# uses embedded SAMPLE_LOGS if no argument provided
python3 pipeline.py

# or provide a log file (JSON array of objects with timestamp, host, message, src_ip)
python3 pipeline.py logs.json
```

Outputs
- A timestamped graph folder is created per run (format: `graphs_YYYYMMDDTHHMMSSZ`) containing PNG provenance graphs
- A JSON report `report_<run_id>.json` is written to the current directory. The report includes events, detections, artifact paths, and the LLM summary (if produced).
- Terminal printed detection report
- If OpenAI is enabled and reachable, a short paragraph will be printed summarizing findings for IT security personnel

Webhook alerts
- To enable webhook alerts for CRITICAL findings, define the environment variables:
	- `ALERT_WEBHOOK_URL` — URL to POST alerts to
	- `ALERT_WEBHOOK_TOKEN` — (optional) Bearer token to include in the Authorization header

Example:

```bash
export ALERT_WEBHOOK_URL="https://hooks.example.com/your/endpoint"
export ALERT_WEBHOOK_TOKEN="s3cr3t-token"
python3 pipeline.py logs.json
```

Machine learning anomaly detection
--------------------------------

This pipeline optionally runs a small unsupervised anomaly detector (IsolationForest) over short sessions of activity. If `scikit-learn` is installed, the pipeline extracts simple session features (failed/successful login counts, outbound transfers, file modifications, distinct ports, duration, event count) and flags anomalous sessions. These anomalies are included in the detections and will trigger graph generation and (optionally) webhook alerts.

To enable ML detection, install `scikit-learn` from `requirements.txt`:

```bash
pip install -r requirements.txt
```

If `scikit-learn` is not installed the pipeline will skip ML-based anomaly detection and continue running heuristic checks only.
