import tempfile
import os
from datetime import datetime
from collections import namedtuple

Event = namedtuple("Event", ["id", "timestamp", "host", "template", "message", "src_ip"])


def parse_iso(ts):
    return datetime.fromisoformat(ts)


def run_drain3_parse(logs):
    """Parse raw log dicts into Event objects using drain3 template miner."""
    try:
        from drain3 import TemplateMiner
        from drain3.file_persistence import FilePersistence
    except Exception as e:
        raise RuntimeError("drain3 is required for parsing logs: " + str(e))

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


def sessionize_events(events, timeout_seconds=600):
    """Group events into sessions by src_ip (or host) using an inactivity timeout."""
    sessions = []
    cur_by_src = {}
    for e in sorted(events, key=lambda x: x.timestamp):
        key = e.src_ip or e.host or "unknown"
        cur = cur_by_src.get(key)
        if cur and (e.timestamp - cur['last_ts']).total_seconds() <= timeout_seconds:
            cur['events'].append(e)
            cur['last_ts'] = e.timestamp
        else:
            if cur:
                cur['end'] = cur['last_ts']
                sessions.append(cur)
            sid = f"{key}-{e.timestamp.isoformat()}"
            cur_by_src[key] = {'session_id': sid, 'src': key, 'start': e.timestamp, 'last_ts': e.timestamp, 'events': [e]}

    for cur in cur_by_src.values():
        cur['end'] = cur['last_ts']
        sessions.append(cur)
    return sessions


# small sample logs kept for convenience
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
