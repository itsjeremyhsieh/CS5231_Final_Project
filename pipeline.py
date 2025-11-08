import argparse
import json
import os
import uuid
from datetime import datetime
import webbrowser
from urllib.parse import quote
import shutil
import copy

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
from reporting import write_json_report


def main():
    parser = argparse.ArgumentParser(description="Run the detection pipeline on a log JSON file")
    parser.add_argument("input", nargs="?", help="input JSON log file (default: sample logs)")
    parser.add_argument("-t", "--threshold", type=int, default=int(os.getenv("DETECTION_THRESHOLD", "50")),
                        help="minimum confidence (0-100) to report a detection (default: 50 or DETECTION_THRESHOLD env)")
    args = parser.parse_args()

    if args.input:
        input_file = args.input
        print(f" Loading logs from {input_file}")
        with open(input_file) as f:
            logs = json.load(f)
    else:
        print(" No file provided; using sample logs.")
        logs = SAMPLE_LOGS

    events = run_drain3_parse(logs)
    print(f"   Parsed {len(events)} events.")
    exploits = detect_exploits(events)
    # apply confidence threshold filter
    threshold = max(0, min(100, int(args.threshold)))
    filtered_exploits = [ex for ex in exploits if ex.get('confidence', 0) >= threshold]

    report_lines = []
    report_lines.append("Exploit Detection Report:")
    if not filtered_exploits:
        report_lines.append(f"No known exploits detected above threshold {threshold}%.")
        print("\n" + report_lines[0])
        print(report_lines[1])
    else:
        print(f"\nExploit Detection Report (threshold >= {threshold}%):")
        for ex in filtered_exploits:
            line = f"- {ex['name']} ({ex['severity']}, {ex['confidence']}%)"
            report_lines.append(line)
            print(line)
            if ex.get("matched"):
                mp = f"   ↪ Matched patterns: {', '.join(ex['matched'])}"
                report_lines.append(mp)
                print(mp)

    timestamp_folder = datetime.now().strftime("graphs_%Y%m%dT%H%M%SZ")
    os.makedirs(timestamp_folder, exist_ok=True)

    graph_entries = []  # list of {path: str, detection_ids: [str], name: str}
    if filtered_exploits:
        for ex in filtered_exploits:
            ex_id = ex['id']
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
            graph_entries.append({"path": path, "detection_ids": [ex_id], "name": ex.get('name')})

    summary_graph = build_graph(events, has_threat=bool(filtered_exploits))
    all_path = draw_graph(summary_graph, postfix="all", title="Provenance: All Events", out_dir=timestamp_folder)
    all_detection_ids = [ex.get('id') for ex in filtered_exploits] if filtered_exploits else []
    graph_entries.append({"path": all_path, "detection_ids": all_detection_ids, "name": "All Events"})

    terminal_output = "\n".join(report_lines)

    report_obj = {
        'run_id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'num_events': len(events),
        'detections': filtered_exploits,
        'detection_threshold': threshold,
        'artifacts': {
            'graphs': graph_entries,
            'folder': timestamp_folder
        }
    }
    report_path = os.path.join(timestamp_folder, f"report_{report_obj['run_id']}.json")
    write_json_report(report_path, report_obj)
    print(f"Wrote JSON report to {report_path}")

    try:
        graph_paths_to_send = [g['path'] for g in graph_entries]
        summary_paragraph = call_openai_for_summary(graph_paths_to_send, terminal_output)
        if summary_paragraph:
            print("\nOpenAI-generated paragraph:\n")
            print(summary_paragraph)
            report_obj['llm_summary'] = summary_paragraph
            write_json_report(report_path, report_obj)
    except Exception as e:
        print(f"OpenAI summary call failed: {e}")

    viewer_path = os.path.abspath("report_viewer.html")
    if os.path.exists(viewer_path):
        try:

            dst_viewer = os.path.join(timestamp_folder, os.path.basename(viewer_path))
            shutil.copy2(viewer_path, dst_viewer)

            with open(viewer_path, 'r', encoding='utf-8') as f:
                viewer_html = f.read()

            embedded_report = copy.deepcopy(report_obj)
            if embedded_report.get('artifacts') and embedded_report['artifacts'].get('graphs'):
                for g in embedded_report['artifacts']['graphs']:
                    try:
                        g['path'] = os.path.basename(g.get('path', ''))
                    except Exception:
                        pass

            embedded_json = json.dumps(embedded_report)
            embedded_json = embedded_json.replace('</', '<\\/')

            embed_tag = f"<script id=\"embeddedReport\" type=\"application/json\">{embedded_json}</script>"

            insert_at = viewer_html.lower().find('<body')
            if insert_at != -1:
                insert_close = viewer_html.find('>', insert_at)
                if insert_close != -1:
                    new_html = viewer_html[: insert_close + 1] + '\n' + embed_tag + '\n' + viewer_html[insert_close + 1 :]
                else:
                    new_html = embed_tag + '\n' + viewer_html
            else:
                # fallback: prepend
                new_html = embed_tag + '\n' + viewer_html

            dst_embedded = os.path.join(timestamp_folder, 'report_viewer_embedded.html')
            with open(dst_embedded, 'w', encoding='utf-8') as f:
                f.write(new_html)

            abs_dst_embedded = os.path.abspath(dst_embedded)
            viewer_url = f"file://{abs_dst_embedded}"
            webbrowser.open(viewer_url)
            print(f"Opened embedded report viewer: {viewer_url}")
            print(f"(embedded viewer written to {dst_embedded}; report path: {report_path})")
        except Exception as e:
            print(f"Failed to open report viewer in browser: {e}")
            print(f"You can open the report manually: {viewer_path}?report={report_path}")
    else:
        print(f"Report viewer not found at {viewer_path}; please open it manually.")


if __name__ == '__main__':
    main()