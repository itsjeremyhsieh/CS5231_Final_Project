import re
import json
import os
import tempfile
import argparse
from datetime import datetime, date

BASE_FIELDS = {
    "host": "localhost",
    "process": "vuln"
}

def parse_syscall(line):
    # tolerant search for syscall-like tokens: name(args)
    match = re.search(r"\b(\w+)\((.*?)\)", line)
    if match:
        syscall, args = match.groups()
        return {
            "message": f"{syscall}({args})",
            "template": syscall,
            "syscall": syscall,
            "args": args
        }
    return None

def parse_crash_line(line):
    # match lines like: "12:00:00.123 +++ killed by SIGSEGV +++" (case-insensitive)
    match = re.search(r"\+\+\+\s*killed by\s+(SIG\w+(?:\s+\S+)*)\s*\+\+\+", line, re.IGNORECASE)
    if match:
        full_sig = match.group(1).strip().upper()
        return {
            "message": f"killed by {full_sig}",
            "template": full_sig.split()[0],
            "syscall": "crash",
            "args": full_sig
        }
    return None


def parse_signal_line(line):
    match = re.search(r"---\s*(SIG\w+).*?---", line, re.IGNORECASE)
    if match:
        sig = match.group(1).upper()
        return {
            "message": line.strip(),
            "template": sig,
            "syscall": "signal",
            "args": sig
        }
    return None


PARSING_RULES = [parse_syscall, parse_signal_line, parse_crash_line]


_time_re = re.compile(r"^\s*(\d{2}:\d{2}:\d{2}\.\d+)")


def _timestamp_from_line_or_now(line):
    m = _time_re.match(line)
    if m:
        t_str = m.group(1)
        try:
            t = datetime.strptime(t_str, "%H:%M:%S.%f").time()
            return datetime.combine(date.today(), t).isoformat()
        except Exception:
            pass
    return datetime.now().isoformat()

def parse_strace_line(line):
    """
    Applies each pattern rule in order and returns the first match.
    Timestamp is taken from the line when present, otherwise now.
    """
    timestamp = _timestamp_from_line_or_now(line)
    base = {"timestamp": timestamp, **BASE_FIELDS}

    for rule in PARSING_RULES:
        try:
            match = rule(line)
        except Exception:
            match = None
        if match:
            return {**base, **match}

    return None  # No rule matched

def main():
    logs = []
    input_path = os.getenv("PARSE_INPUT", "log.txt")
    output_path = os.getenv("PARSE_OUTPUT", "logs.json")

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            parsed = parse_strace_line(line)
            if parsed:
                logs.append(parsed)

    dirn = os.path.dirname(os.path.abspath(output_path)) or "."
    with tempfile.NamedTemporaryFile("w", delete=False, dir=dirn, encoding="utf-8") as tf:
        json.dump(logs, tf, indent=2, ensure_ascii=False)
        tmpname = tf.name
    os.replace(tmpname, output_path)
    print(f"Parsed {len(logs)} log entries → saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse strace-like logs into JSON records.")
    parser.add_argument("-i", "--input", nargs='?', help="Input text file to parse (default: log.txt)", default=None)
    parser.add_argument("-o", "--output", help="Output JSON file (default: logs.json)", default=None)
    args = parser.parse_args()

    # if CLI args provided, override environment/defaults
    if args.input:
        os.environ["PARSE_INPUT"] = args.input
    if args.output:
        os.environ["PARSE_OUTPUT"] = args.output

    main()