# CS5231 Systems Security Final Project: Traced-based Exploit Detection

This project contains a pipeline that parses log messages, detects known exploitation patterns, builds provenance graphs, and asks OpenAI to generate a concise paragraph for IT security staff summarizing findings.

Features
- Template mining using drain3 to cluster log message templates
- Heuristic exploit detection (SSH brute force, privilege escalation, port scanning, SQL/command injection, buffer overflow, data exfiltration)
- Provenance graph generation (NetworkX + Matplotlib)
- Optional OpenAI integration to produce an actionable paragraph (requires `OPENAI_API_KEY`)

Quick start

1. Create and activate a Python virtual environment:

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

5. To collect logs from syslog, you can run `strace -tt -T -o trace-vuln.log ./vuln` and then parse `trace-vuln.log` to extract relevant log messages into a JSON file.

Outputs
- A timestamped graph folder is created per run (format: `graphs_YYYYMMDDTHHMMSSZ`) containing PNG provenance graphs
- A JSON report `report_<run_id>.json` is written to the current directory. The report includes events, detections, artifact paths, and the LLM summary (if produced).
- Terminal printed detection report
- If OpenAI is enabled and reachable, a short paragraph will be printed summarizing findings for IT security personnel
