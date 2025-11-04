import json
import os
import sys
import tempfile
import os
import sys
import json
import uuid
from datetime import datetime

missing = []
for mod in ("drain3", "networkx", "matplotlib", "openai", "requests"):
    try:
        __import__(mod)
    except Exception:
        missing.append(mod)
if missing:
    print("Missing packages:", ", ".join(missing))
    print("Install with: pip3 install " + " ".join(missing))

from parser import run_drain3_parse, sessionize_events, SAMPLE_LOGS
from detector import detect_exploits
from graph import build_graph, draw_graph
from openai_client import call_openai_for_summary
from reporting import write_json_report, send_webhook_alert


def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        print(f" Loading logs from {input_file}")
        with open(input_file) as f:
            logs = json.load(f)
    else:
        print(" No file provided; using sample logs.")
        logs = SAMPLE_LOGS

    events = run_drain3_parse(logs)
    print(f"   Parsed {len(events)} events.")
    exploits = detect_exploits(events)

    report_lines = []
    report_lines.append("Exploit Detection Report:")
    if not exploits:
        report_lines.append("No known exploits detected.")
        print("\n" + report_lines[0])
        print(report_lines[1])
    else:
        print("\nExploit Detection Report:")
        for ex in exploits:
            line = f"- {ex['name']} ({ex['severity']}, {ex['confidence']}%)"
            report_lines.append(line)
            print(line)
            if ex.get("matched"):
                mp = f"   ↪ Matched patterns: {', '.join(ex['matched'])}"
                report_lines.append(mp)
                print(mp)

    # Create a timestamped output folder for this run's artifacts
    timestamp_folder = datetime.utcnow().strftime("graphs_%Y%m%dT%H%M%SZ")
    os.makedirs(timestamp_folder, exist_ok=True)

    # sessionize (kept for operator inspection)
    sessions = sessionize_events(events, timeout_seconds=600)

    graph_paths = []
    if exploits:
        for ex in exploits:
            ex_id = ex['id']
            # if detection provides explicit evidence event ids, use those
            if ex.get('evidence_event_ids'):
                relevant_events = [e for e in events if e.id in ex['evidence_event_ids']]
            else:
                matched_patterns = [p.lower() for p in ex.get('matched', [])]
                relevant_events = [e for e in events if any(p in e.message.lower() for p in matched_patterns)]
            if not relevant_events:
                continue
            print(f"\nBuilding graph for {ex['name']} with {len(relevant_events)} events...")
            G = build_graph(relevant_events, has_threat=True)
            path = draw_graph(G, postfix=ex_id, title=f"Provenance: {ex['name']}", out_dir=timestamp_folder)
            graph_paths.append(path)

    summary_graph = build_graph(events, has_threat=bool(exploits))
    all_path = draw_graph(summary_graph, postfix="all", title="Provenance: All Events", out_dir=timestamp_folder)
    graph_paths.append(all_path)

    terminal_output = "\n".join(report_lines)

    # write JSON report
    report_obj = {
        'run_id': str(uuid.uuid4()),
        'timestamp': datetime.utcnow().isoformat(),
        'num_events': len(events),
        'detections': exploits,
        'artifacts': {
            'graphs': graph_paths,
            'folder': timestamp_folder
        }
    }
    report_path = os.path.join(timestamp_folder, f"report_{report_obj['run_id']}.json")
    write_json_report(report_path, report_obj)
    print(f"Wrote JSON report to {report_path}")

    try:
        summary_paragraph = call_openai_for_summary(graph_paths, terminal_output)
        if summary_paragraph:
            print("\nOpenAI-generated paragraph:\n")
            print(summary_paragraph)
            report_obj['llm_summary'] = summary_paragraph
            write_json_report(report_path, report_obj)
    except Exception as e:
        print(f"OpenAI summary call failed: {e}")


if __name__ == '__main__':
    main()