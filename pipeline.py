import json
import os
import sys
import tempfile
from datetime import datetime
from collections import namedtuple, defaultdict

missing = []
try:
    from drain3 import TemplateMiner
    from drain3.file_persistence import FilePersistence
except ImportError:
    missing.append("drain3")
try:
    import networkx as nx
    import matplotlib.pyplot as plt
except ImportError:
    missing.append("networkx and matplotlib")

if missing:
    print("Missing packages:", ", ".join(missing))
    print("Install with: pip install " + " ".join(missing))
    sys.exit(1)

# -------------------- KNOWN EXPLOITS --------------------
KNOWN_EXPLOITS = {
    "brute_force_ssh": {
        "name": "SSH Brute Force Attack",
        "description": "Multiple failed login attempts followed by success",
        "severity": "HIGH",
        "patterns": ["Failed login", "Failed password", "Invalid user", "Successful login"],
        "indicators": {"min_failed_attempts": 3}
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "User elevates privileges and modifies system files",
        "severity": "CRITICAL",
        "patterns": ["sudo", "su -", "modified", "/etc/passwd", "/etc/shadow"],
        "indicators": {
            "system_files": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"],
            "privileged_user": ["root", "admin"]
        }
    },
    "port_scanning": {
        "name": "Network Port Scanning",
        "description": "Reconnaissance activity - scanning multiple ports",
        "severity": "MEDIUM",
        "patterns": ["port scan", "connection attempt", "SYN"],
        "indicators": {
            "min_scan_events": 2
        }
    },
    "sql_injection": {
        "name": "SQL Injection Attempt",
        "severity": "HIGH",
        "patterns": ["SQL", "injection", "' OR '1'='1", "UNION SELECT", "DROP TABLE"]
    },
    "command_injection": {
        "name": "Command Injection",
        "severity": "CRITICAL",
        "patterns": ["; cat", "&& whoami", "| nc", "/bin/sh", "/bin/bash"]
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "severity": "CRITICAL",
        "patterns": ["scp", "rsync", "curl", "wget", "unusual outbound"]
    },
    "buffer_overflow": {
        "name": "Buffer Overflow Attempt",
        "description": "Crash due to stack smashing or memory corruption",
        "severity": "CRITICAL",
        "patterns": ["SIGSEGV", "core dumped", "stack smashing detected", "memory violation", "killed by SIGSEGV"]
    },
}

# -------------------- SAMPLE DATA --------------------
SAMPLE_LOGS = [
    {"timestamp": "2025-10-22T10:00:00", "host": "hostA", "message": "Failed login for user root", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T10:00:05", "host": "hostA", "message": "Failed login for user root", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T10:00:10", "host": "hostA", "message": "Failed login for user root", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T10:00:20", "host": "hostA", "message": "Successful login for user root", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T10:05:00", "host": "hostA", "message": "Sudo executed by user root: apt-get update", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T10:06:00", "host": "hostA", "message": "File /etc/passwd modified by uid=0", "src_ip": "10.0.0.5"},
    {"timestamp": "2025-10-22T11:10:00", "host": "hostB", "message": "Port scan detected from 10.0.0.7", "src_ip": "10.0.0.7"},
    {"timestamp": "2025-10-22T11:10:05", "host": "hostB", "message": "Port scan detected from 10.0.0.7", "src_ip": "10.0.0.7"},
    {"timestamp": "2025-10-22T11:10:20", "host": "hostB", "message": "Connection from 10.0.0.7 to 192.168.1.11:22", "src_ip": "10.0.0.7"},
    {"timestamp": "2025-10-22T12:00:00", "host": "hostC", "message": "SIGSEGV received by pid 432", "src_ip": "10.0.0.9"},
    {"timestamp": "2025-10-22T12:00:10", "host": "hostC", "message": "core dumped in /var/crash", "src_ip": "10.0.0.9"},
    {"timestamp": "2025-10-22T12:20:00", "host": "hostD", "message": "' OR '1'='1 -- login bypass", "src_ip": "10.0.0.11"}
]

# -------------------- STRUCTURE ---------------------
Event = namedtuple("Event", ["id", "timestamp", "host", "template", "message", "src_ip"])

def parse_iso(ts):
    return datetime.fromisoformat(ts)

def run_drain3_parse(logs):
    tmpdir = tempfile.mkdtemp()
    miner = TemplateMiner(FilePersistence(os.path.join(tmpdir, "state.bin")))

    events = []
    for i, log in enumerate(logs):
        msg = log["message"]
        result = miner.add_log_message(msg)
        template = result.get("template_mined") or result.get("template") or msg
        events.append(Event(
            id=i,
            timestamp=parse_iso(log["timestamp"]),
            host=log["host"],
            template=template,
            message=msg,
            src_ip=log.get("src_ip", "")
        ))
    return sorted(events, key=lambda e: e.timestamp)

def detect_exploits(events):
    detected = []
    event_msgs = [e.message.lower() for e in events]
    
    for exploit_id, exploit in KNOWN_EXPLOITS.items():
        matched_patterns = set()
        confidence = 0

        # Match patterns
        for pattern in exploit.get("patterns", []):
            pattern_lc = pattern.lower()
            for msg in event_msgs:
                if pattern_lc in msg:
                    matched_patterns.add(pattern)
                    confidence += 10  

        # Special exploit-specific logic
        if exploit_id == "brute_force_ssh":
            failed_login_count = sum("failed login" in msg for msg in event_msgs)
            success_login = any("successful login" in msg for msg in event_msgs)
            if failed_login_count >= exploit['indicators'].get("min_failed_attempts", 3) and success_login:
                confidence += 40

        elif exploit_id == "privilege_escalation":
            has_sudo = any("sudo" in msg or "su -" in msg for msg in event_msgs)
            system_mod = any(any(f in msg for f in exploit["indicators"]["system_files"]) for msg in event_msgs)
            if has_sudo and system_mod:
                confidence += 50

        elif exploit_id == "port_scanning":
            scan_events = sum("port scan" in msg or "syn" in msg or "connection attempt" in msg for msg in event_msgs)
            if scan_events >= exploit["indicators"].get("min_scan_events", 2):
                confidence += 40

        elif exploit_id == "data_exfiltration":
            file_access = any("access" in msg or "open" in msg for msg in event_msgs)
            outbound = any("scp" in msg or "wget" in msg or "curl" in msg or "rsync" in msg for msg in event_msgs)
            if outbound:
                confidence += 20
                if file_access:
                    confidence += 20

        elif exploit_id == "sql_injection":
            if any(("union select" in msg or "' or '" in msg or "drop table" in msg or "sql" in msg) for msg in event_msgs):
                confidence += 50

        elif exploit_id == "command_injection":
            if any(t in msg for t in ["; cat", "&& whoami", "| nc", "/bin/sh", "/bin/bash"] for msg in event_msgs):
                confidence += 50

        elif exploit_id == "buffer_overflow":
            if any("sigsegv" in msg or "core dumped" in msg or "stack smashing" in msg or "memory violation" in msg for msg in event_msgs):
                confidence += 50

        if confidence > 0:
            detected.append({
                "id": exploit_id,
                "name": exploit["name"],
                "severity": exploit.get("severity", "UNKNOWN"),
                "confidence": min(confidence, 100),
                "matched": list(matched_patterns)
            })

    return detected

def build_graph(events, has_threat):
    import networkx as nx
    G = nx.DiGraph()
    for i, e in enumerate(events):
        G.add_node(e.id,
                   label=(e.template[:30] + "..." if len(e.template) > 30 else e.template),
                   color="red" if has_threat else "lightblue",
                   ts=e.timestamp.isoformat())
        if i > 0:
            G.add_edge(events[i - 1].id, e.id)
    return G

def draw_graph(G, postfix="", title="Provenance Graph"):

    pos = nx.spring_layout(G, seed=42)
    colors = [G.nodes[n]["color"] for n in G.nodes()]
    labels = {n: G.nodes[n]["label"] for n in G.nodes()}
    plt.figure(figsize=(12, 6))
    nx.draw(G, pos, node_color=colors, node_size=1000, with_labels=False)
    nx.draw_networkx_labels(G, pos, labels, font_size=8)
    nx.draw_networkx_edges(G, pos, arrows=True)
    plt.title(title)
    out_path = f"provenance_graph_{postfix}.png"
    plt.savefig(out_path)
    plt.close()
    print(f"    Saved graph to {out_path}")

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

    print("\nExploit Detection Report:")
    if not exploits:
        print("No known exploits detected.")
    else:
        for ex in exploits:
            print(f"- {ex['name']} ({ex['severity']}, {ex['confidence']}%)")
            if ex["matched"]:
                print(f"   ↪ Matched patterns: {', '.join(ex['matched'])}")

        for ex in exploits:
            ex_id = ex['id']
            matched_patterns = [p.lower() for p in ex['matched']]
            relevant_events = [e for e in events if any(p in e.message.lower() for p in matched_patterns)]
            if not relevant_events:
                continue
            print(f"\nBuilding graph for {ex['name']} with {len(relevant_events)} events...")
            G = build_graph(relevant_events, has_threat=True)
            draw_graph(G, postfix=ex_id, title=f"Provenance: {ex['name']}")

    summary_graph = build_graph(events, has_threat=bool(exploits))
    draw_graph(summary_graph, postfix="all", title="Provenance: All Events")

if __name__ == "__main__":
    main()