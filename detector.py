import re
from collections import defaultdict

# Known exploits and rules
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


def detect_exploits(events):
    compiled = {}
    for eid, ex in KNOWN_EXPLOITS.items():
        compiled[eid] = [re.compile(p, re.IGNORECASE) for p in ex.get("patterns", [])]

    events_by_src = defaultdict(list)
    for e in events:
        key = e.src_ip or e.host or "unknown"
        events_by_src[key].append(e)

    detected = []

    def window_count(ev_list, regex, window_seconds=300):
        ev_list_sorted = sorted(ev_list, key=lambda x: x.timestamp)
        counts = 0
        for i, ev in enumerate(ev_list_sorted):
            if regex.search(ev.message):
                tstart = ev.timestamp
                for ev2 in ev_list_sorted[i:]:
                    if (ev2.timestamp - tstart).total_seconds() <= window_seconds:
                        if regex.search(ev2.message):
                            counts += 1
                    else:
                        break
        return counts

    for exploit_id, exploit in KNOWN_EXPLOITS.items():
        matched_patterns = set()
        confidence = 0

        for reg in compiled.get(exploit_id, []):
            if any(reg.search(e.message) for e in events):
                matched_patterns.add(reg.pattern)
                confidence += 5

        for src, evs in events_by_src.items():

            if exploit_id == "brute_force_ssh":
                failed_re = re.compile(r"failed (login|password)", re.IGNORECASE)
                success_re = re.compile(r"successful login|accepted password", re.IGNORECASE)
                failed_count = window_count(evs, failed_re, window_seconds=300)
                success_after = any(
                    success_re.search(e.message) and any(failed_re.search(e2.message) and e2.timestamp <= e.timestamp for e2 in evs)
                    for e in evs
                )
                if failed_count >= exploit.get("indicators", {}).get("min_failed_attempts", 3) and success_after:
                    confidence += 60
                    matched_patterns.add("failed login / successful login pattern")

            elif exploit_id == "privilege_escalation":
                sudo_re = re.compile(r"\b(sudo|su -)\b", re.IGNORECASE)
                system_files = exploit.get("indicators", {}).get("system_files", [])
                file_re = re.compile("|".join([re.escape(p) for p in system_files]), re.IGNORECASE) if system_files else None
                has_sudo = any(sudo_re.search(e.message) for e in evs)
                system_mod = any(file_re.search(e.message) for e in evs) if file_re else False
                if has_sudo and system_mod:
                    confidence += 70
                    matched_patterns.add("sudo and system file modification")

            elif exploit_id == "port_scanning":
                port_re = re.compile(r":(\d+)|port\s+(\d+)", re.IGNORECASE)
                ports = set()
                for e in evs:
                    m = port_re.search(e.message)
                    if m:
                        ports.add(m.group(1) or m.group(2))
                if len(ports) >= exploit.get("indicators", {}).get("min_scan_events", 2):
                    confidence += 50
                    matched_patterns.add(f"ports: {', '.join(sorted(ports))}")

            elif exploit_id == "data_exfiltration":
                outbound_re = re.compile(r"\b(scp|rsync|curl|wget)\b", re.IGNORECASE)
                file_access_re = re.compile(r"\b(open|read|access)\b", re.IGNORECASE)
                if any(outbound_re.search(e.message) for e in evs):
                    confidence += 25
                    if any(file_access_re.search(e.message) for e in evs):
                        confidence += 25
                        matched_patterns.add("outbound transfer + file access")

            elif exploit_id == "sql_injection":
                sql_re = re.compile(r"union select|' or '|drop table|select .* from", re.IGNORECASE)
                if any(sql_re.search(e.message) for e in evs):
                    confidence += 60
                    matched_patterns.add("sql-like payloads")

            elif exploit_id == "command_injection":
                cmd_re = re.compile(r"(;\s*cat|&&\s*whoami|\|\s*nc|/bin/(sh|bash))", re.IGNORECASE)
                if any(cmd_re.search(e.message) for e in evs):
                    confidence += 70
                    matched_patterns.add("command injection indicators")

            elif exploit_id == "buffer_overflow":
                bof_re = re.compile(r"sigsegv|core dumped|stack smashing|memory violation", re.IGNORECASE)
                if any(bof_re.search(e.message) for e in evs):
                    confidence += 65
                    matched_patterns.add("crash / core / SIGSEGV")

        if confidence > 0:
            detected.append({
                "id": exploit_id,
                "name": exploit.get("name", exploit_id),
                "severity": exploit.get("severity", "UNKNOWN"),
                "confidence": min(confidence, 100),
                "matched": list(matched_patterns)
            })

    return detected
