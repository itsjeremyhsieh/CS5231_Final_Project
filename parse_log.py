import re
import json
from datetime import datetime

BASE_FIELDS = {
    "host": "localhost",
    "process": "vuln"
}

def parse_syscall(line):
    match = re.match(r"\d{2}:\d{2}:\d{2}\.\d+\s+(\w+)\((.*?)\)", line)
    if match:
        syscall, args = match.groups()
        return {
            "message": f"{syscall}({args})",
            "template": syscall,
            "syscall": syscall,
            "args": args
        }
    return None

def parse_signal_line(line):
    match = re.match(r"\d{2}:\d{2}:\d{2}\.\d+\s+---\s+(SIG\w+).*?---", line)
    if match:
        sig = match.group(1)
        return {
            "message": line.strip(),
            "template": sig,
            "syscall": "signal",
            "args": sig
        }
    return None

def parse_crash_line(line):
    match = re.match(r"\d{2}:\d{2}:\d{2}\.\d+\s+\+\+\+\s*killed by\s+(SIG\w+.*?)\s*\+\+\+", line.lower())
    if match:
        full_sig = match.group(1).upper()
        return {
            "message": f"killed by {full_sig}",
            "template": full_sig.split()[0],  # e.g., SIGSEGV
            "syscall": "crash",
            "args": full_sig
        }
    return None


PARSING_RULES = [parse_syscall, parse_signal_line, parse_crash_line]

def parse_strace_line(line):
    """
    Applies each pattern rule in order and returns the first match.
    """
    timestamp = datetime.now().isoformat()
    base = {
        "timestamp": timestamp,
        **BASE_FIELDS
    }

    for rule in PARSING_RULES:
        match = rule(line)
        if match:
            return {**base, **match}

    return None  # No rule matched

def main():
    logs = []
    with open("log.txt") as f:
        for line in f:
            parsed = parse_strace_line(line)
            if parsed:
                logs.append(parsed)
    with open("logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Parsed {len(logs)} log entries → saved to logs.json ✅")

if __name__ == "__main__":
    main()