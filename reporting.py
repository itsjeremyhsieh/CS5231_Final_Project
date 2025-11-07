import json
import time

try:
    import requests
except Exception:
    requests = None


def write_json_report(path, report_obj):
    with open(path, "w") as f:
        json.dump(report_obj, f, indent=2, default=str)
