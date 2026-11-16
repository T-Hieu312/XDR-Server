from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ai.datasets import iter_db_events
from ai.detector import AnomalyDetector, model_path
from ai.features import WINDOW_SECONDS, group_windows, window_features
from ai.scenarios import (BENIGN, ScenarioClassifier, heuristic_scenario, scenario_info,
                          scenario_model_path)
from database.database import analyzed_window_keys, get_database_path, save_ai_window
from detection.rule_engine import load_default_rules

log = logging.getLogger("xdr.ai")

# Hints only: which ATT&CK technique a strongly deviating feature usually points to.
FEATURE_MITRE_HINTS = {
    "suspicious_cmdline_count": "T1059.001",
    "shell_process_count": "T1059",
    "lolbin_process_count": "T1218",
    "office_spawn_count": "T1566.001",
    "user_writable_exec_count": "T1204.002",
    "unique_dst_port": "T1046",
    "unique_dst_ip": "T1046",
    "external_connection_count": "T1071",
    "max_domain_entropy": "T1568.002",
    "executable_file_create_count": "T1105",
    "persistence_registry_count": "T1547.001",
    "lsass_access_count": "T1003.001",
    "auth_failure_count": "T1110",
    "auth_failure_src_count": "T1110",
    "ids_bruteforce_count": "T1110",
    "rdp_logon_count": "T1021.001",
    "auth_success_after_failures": "T1078",
    "ids_scan_count": "T1046",
    "ids_web_attack_count": "T1190",
    "web_attack_count": "T1190",
    "sqli_count": "T1190",
    "ids_dos_count": "T1498",
    "discovery_cmd_count": "T1087",
    "credential_dump_cmd_count": "T1003",
    "remote_exec_count": "T1021.002",
    "service_install_count": "T1543.003",
    "account_change_count": "T1136.001",
    "defense_evasion_count": "T1070.001",
    "inhibit_recovery_count": "T1490",
    "ransom_note_count": "T1486",
    "long_dns_query_count": "T1071.004",
    "max_dns_query_length": "T1048.003",
}
HIGH_SEVERITY_SCENARIOS = {"rdp_compromise", "credential_access", "sql_injection", "command_and_control",
                           "lateral_movement", "ransomware", "defense_evasion", "account_manipulation",
                           "dns_tunneling", "dos"}
CRITICAL_SCENARIOS = {"ransomware"}

_lock = threading.Lock()
_cache: dict[str, tuple[tuple[str, float], Any]] = {}


def _cached(name: str, path: Path, loader) -> Any:
    """Load a model once and reload it when its file changes (after retraining)."""
    if not path.exists():
        _cache.pop(name, None)
        return None
    key = (str(path.resolve()), path.stat().st_mtime)
    if name not in _cache or _cache[name][0] != key:
        _cache[name] = (key, loader(path))
        log.info("Loaded AI %s %s", name, getattr(_cache[name][1], "version", None))
    return _cache[name][1]


def get_detector() -> AnomalyDetector | None:
    return _cached("anomaly model", model_path(), AnomalyDetector.load)


def get_scenario_classifier() -> ScenarioClassifier | None:
    return _cached("scenario model", scenario_model_path(), ScenarioClassifier.load)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def assess_window(row: dict[str, float], anomaly: dict[str, Any], detector: AnomalyDetector,
                  classified: dict[str, Any] | None) -> dict[str, Any]:
    """Combine tier 1 (anomaly: is it unusual?) and tier 2 (scenario: which attack is it?).

    A window is alerted when it is anomalous OR the classifier recognises a known
    attack scenario with enough confidence. The scenario name comes from the
    classifier when it recognises one, otherwise from the deviating features.
    """
    classifier_hit = bool(classified and classified["is_attack"])
    if classifier_hit:
        scenario = dict(classified)
    elif anomaly["is_anomaly"]:
        scenario = heuristic_scenario(detector.explain(row, limit=None))
        if classified:
            scenario["classifier"] = {k: classified[k] for k in ("id", "confidence", "probabilities")}
    else:
        scenario = {**scenario_info(BENIGN), "source": "classifier" if classified else "anomaly_model",
                    "confidence": classified["confidence"] if classified else round(1 - anomaly["ai_score"], 4)}
    final_score = max(anomaly["ai_score"], scenario["confidence"] if classifier_hit else 0.0)
    return {
        **anomaly,
        "is_alert": bool(anomaly["is_anomaly"] or classifier_hit),
        "final_score": round(final_score, 4),
        "detected_by": [name for name, hit in (("anomaly", anomaly["is_anomaly"]),
                                               ("classifier", classifier_hit)) if hit],
        "scenario": scenario,
    }


def build_anomaly_alert(host_id: str, result: dict[str, Any], event_id: str) -> dict[str, Any]:
    top = result["top_features"]
    scenario = result.get("scenario") or scenario_info("unknown")
    reason = ", ".join(f"{item['feature']}={item['value']:g}" for item in top) or "unusual feature combination"
    mitre = {FEATURE_MITRE_HINTS[item["feature"]] for item in top if item["feature"] in FEATURE_MITRE_HINTS}
    mitre.update(scenario.get("mitre", []))
    score = result.get("final_score", result["ai_score"])
    return {
        "rule_id": "ai-anomaly",
        "title": f"AI: {scenario['label']} trên {host_id} ({reason})",
        "severity": ("critical" if scenario["id"] in CRITICAL_SCENARIOS
                     else "high" if score >= 0.8 or scenario["id"] in HIGH_SEVERITY_SCENARIOS else "medium"),
        "confidence": 0.8,
        "mitre_attack": sorted(mitre),
        "event_id": event_id,
    }


def analyze_pending(now: datetime | None = None, lookback_minutes: int | None = None,
                    grace_seconds: int | None = None) -> dict[str, Any]:
    """Score every closed, not-yet-analysed window in the lookback horizon."""
    with _lock:
        detector = get_detector()
        if detector is None:
            return {"status": "model_not_trained", "model_path": str(model_path())}
        classifier = get_scenario_classifier()

        now = now or datetime.now(timezone.utc)
        lookback = timedelta(minutes=lookback_minutes or int(os.environ.get("XDR_AI_LOOKBACK_MINUTES", "120")))
        grace = timedelta(seconds=grace_seconds if grace_seconds is not None
                          else int(os.environ.get("XDR_AI_GRACE_SECONDS", "120")))
        horizon_start = now - lookback
        closed_before = now - grace

        # Stored timestamps are ISO text; widen the SQL range by a day to tolerate
        # non-UTC offsets, then filter precisely after parsing.
        events = list(iter_db_events(get_database_path(), since=_iso(horizon_start - timedelta(days=1))[:19],
                                     until=_iso(now + timedelta(days=1))[:19]))
        done = analyzed_window_keys(_iso(horizon_start - timedelta(seconds=WINDOW_SECONDS)))

        pending = []
        for (host_id, start), window_events in group_windows(events).items():
            end = start + timedelta(seconds=WINDOW_SECONDS)
            if start < horizon_start or end > closed_before or (host_id, _iso(start)) in done:
                continue
            pending.append((host_id, start, end, window_events))
        summary = {"status": "ok", "model_version": detector.version,
                   "scenario_model_version": classifier.version if classifier else None}
        if not pending:
            return {**summary, "analyzed": 0, "anomalies": 0, "scenarios": {}}

        rows = [window_features(window_events) for _, _, _, window_events in pending]
        anomalies = detector.score_many(rows)
        classified = classifier.predict_many(rows) if classifier else [None] * len(rows)
        confidence = {str(rule.get("id")): float(rule.get("confidence", 1.0)) for rule in load_default_rules()}

        alerts = 0
        scenarios: dict[str, int] = {}
        for (host_id, start, end, window_events), features, anomaly, scen in zip(pending, rows, anomalies, classified):
            result = assess_window(features, anomaly, detector, scen)
            event_ids = [str(event["event_id"]) for event in window_events]
            alert = None
            if result["is_alert"]:
                alerts += 1
                scenarios[result["scenario"]["id"]] = scenarios.get(result["scenario"]["id"], 0) + 1
                alert = build_anomaly_alert(host_id, result, event_ids[-1])
            save_ai_window(
                {"host_id": host_id, "window_start": _iso(start), "window_end": _iso(end),
                 "event_count": len(window_events), "features": features},
                result, event_ids, alert, confidence,
            )
        log.info("AI analysed %s windows, %s alerts %s", len(pending), alerts, scenarios)
        return {**summary, "analyzed": len(pending), "anomalies": alerts, "scenarios": scenarios}
