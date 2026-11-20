#!/usr/bin/env python3
"""Ship Suricata eve.json events to the XDR collector.

Follows eve.json like `tail -F` (survives log rotation), sends events in
batches and remembers its position in a state file, so a restart neither
loses nor re-sends events. When XDR is unreachable it retries without
advancing. Standard library only (Python 3.8+).

    XDR_SURICATA_INGEST_KEY=... python3 suricata_to_xdr.py \
        --url http://10.10.40.10:8000/api/collectors/suricata/events
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

MAX_BATCH = 500             # XDR collector limit
MAX_BODY = 1_800_000        # stay under the 2 MiB request limit


def log(message):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), message, flush=True)


def load_state(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(path, inode, offset):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({"inode": inode, "offset": offset}, handle)
    os.replace(tmp, path)


def post(url, key, collector_id, events, timeout=10):
    body = json.dumps({"events": events}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "X-Collector-Key": key, "X-Collector-Id": collector_id})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def read_batch(handle, types, batch_size):
    """Read complete lines from the current position. Returns (events, new_offset)."""
    events, size = [], 0
    offset = handle.tell()
    while len(events) < batch_size and size < MAX_BODY:
        line = handle.readline()
        if not line:
            break
        if not line.endswith(b"\n"):      # Suricata is still writing this line
            handle.seek(offset)
            break
        offset = handle.tell()
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not types or event.get("event_type") in types:
            events.append(event)
            size += len(line)
    return events, offset


def run(args, key):
    state = load_state(args.state)
    handle, inode = None, None
    backoff = 1
    while True:
        try:
            stat = os.stat(args.eve)
        except FileNotFoundError:
            time.sleep(args.interval)
            continue
        if handle is None or stat.st_ino != inode or stat.st_size < handle.tell():
            if handle:
                handle.close()
                log("eve.json rotated, reading the new file from the start")
                state = {}
            handle = open(args.eve, "rb")
            inode = stat.st_ino
            if state.get("inode") == inode and state.get("offset", 0) <= stat.st_size:
                handle.seek(state["offset"])
            elif not args.from_start and not state:
                handle.seek(0, os.SEEK_END)   # first run: only new events
            log(f"following {args.eve} from offset {handle.tell()}")

        start = handle.tell()
        events, offset = read_batch(handle, args.types, args.batch)
        if events:
            try:
                result = post(args.url, key, args.collector_id, events)
                log(f"sent {len(events)} events: {result}")
                backoff = 1
            except urllib.error.HTTPError as error:
                detail = error.read(300).decode("utf-8", "replace")
                log(f"XDR rejected batch: HTTP {error.code} {detail}")
                if error.code in (401, 403, 503):
                    handle.seek(start)        # configuration problem: keep the events, wait
                    time.sleep(30)
                    continue
                # 4xx on the payload itself: skip this batch so one bad event cannot block the rest
            except (urllib.error.URLError, OSError) as error:
                log(f"cannot reach XDR: {error}; retrying in {backoff}s")
                handle.seek(start)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
        if offset != state.get("offset") or inode != state.get("inode"):
            save_state(args.state, inode, offset)
            state = {"inode": inode, "offset": offset}
        if len(events) < args.batch:
            time.sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(description="Ship Suricata eve.json events to XDR")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--url", default=os.environ.get("XDR_SURICATA_URL"),
                        help="http://<xdr>:8000/api/collectors/suricata/events")
    parser.add_argument("--collector-id", default=os.environ.get("XDR_COLLECTOR_ID", "suricata-lab"))
    parser.add_argument("--types", nargs="*", default=["alert"],
                        help="eve event_type values to send (default: alert; empty = all)")
    parser.add_argument("--batch", type=int, default=200)
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between polls")
    parser.add_argument("--state", default="/var/lib/suricata-xdr/state.json")
    parser.add_argument("--from-start", action="store_true", help="On first run send the whole file")
    args = parser.parse_args()
    key = os.environ.get("XDR_SURICATA_INGEST_KEY")
    if not args.url or not key:
        sys.exit("Set --url (or XDR_SURICATA_URL) and the XDR_SURICATA_INGEST_KEY environment variable")
    args.batch = max(1, min(args.batch, MAX_BATCH))
    os.makedirs(os.path.dirname(os.path.abspath(args.state)), exist_ok=True)
    try:
        run(args, key)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
