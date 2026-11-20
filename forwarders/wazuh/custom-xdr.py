#!/usr/bin/env python3
"""Wazuh integration: forward each Wazuh alert to the XDR collector.

Installed as /var/ossec/integrations/custom-xdr.py (called through the
custom-xdr wrapper). Wazuh runs it once per alert as:

    custom-xdr <alert_file> <api_key> <hook_url>

<api_key> is the XDR_WAZUH_INGEST_KEY of the XDR server and <hook_url> is
http://<xdr>:8000/api/collectors/wazuh/events. Standard library only.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

LOG_FILE = "/var/ossec/logs/integrations.log"


def log(message):
    line = f"{datetime.now(timezone.utc).isoformat()} custom-xdr: {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


def read_alert(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read().strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(text.splitlines()[0])  # some versions append extra lines


def send(alert, api_key, hook_url, retries=3):
    body = json.dumps({"alerts": [alert]}).encode("utf-8")
    request = urllib.request.Request(
        hook_url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Collector-Key": api_key},
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=5):
                return True
        except urllib.error.HTTPError as error:
            detail = error.read(300).decode("utf-8", "replace")
            log(f"XDR rejected alert {alert.get('id')}: HTTP {error.code} {detail}")
            if error.code < 500:
                return False  # wrong key / bad payload: retrying will not help
        except (urllib.error.URLError, OSError) as error:
            log(f"cannot reach XDR ({hook_url}) attempt {attempt}/{retries}: {error}")
        time.sleep(attempt)
    return False


def main(argv):
    if len(argv) < 4:
        log("usage: custom-xdr <alert_file> <api_key> <hook_url>")
        return 1
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    try:
        alert = read_alert(alert_file)
    except (OSError, ValueError, IndexError) as error:
        log(f"cannot read alert file {alert_file}: {error}")
        return 1
    return 0 if send(alert, api_key, hook_url) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
