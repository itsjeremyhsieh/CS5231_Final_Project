import json
import time

try:
    import requests
except Exception:
    requests = None


def write_json_report(path, report_obj):
    with open(path, "w") as f:
        json.dump(report_obj, f, indent=2, default=str)


def send_webhook_alert(report_obj, webhook_url, token=None, retries=2):
    if requests is None:
        raise RuntimeError("requests library is required to send webhook alerts")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {"timestamp": time.time(), "report": report_obj}
    for i in range(retries + 1):
        try:
            r = requests.post(webhook_url, json=payload, headers=headers, timeout=6)
            if 200 <= r.status_code < 300:
                return True
        except Exception:
            pass
    return False
