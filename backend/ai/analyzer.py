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
}

_lock = threading.Lock()
_detector: AnomalyDetector | None = None
_detector_key: tuple[str, float] | None = None


def get_detector() -> AnomalyDetector | None:
    """Load the model once and reload it when the model file changes (after retraining)."""
    global _detector, _detector_key
    path: Path = model_path()
    if not path.exists():
        _detector, _detector_key = None, None
        return None
    key = (str(path.resolve()), path.stat().st_mtime)
    if _detector is None or key != _detector_key:
        _detector = AnomalyDetector.load(path)
        _detector_key = key
        log.info("Loaded AI model %s", _detector.version if _detector else None)
    return _detector


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def build_anomaly_alert(host_id: str, result: dict[str, Any], event_id: str) -> dict[str, Any]:
    top = result["top_features"]
    reason = ", ".join(f"{item['feature']}={item['value']:g}" for item in top) or "unusual feature combination"
    mitre = sorted({FEATURE_MITRE_HINTS[item["feature"]] for item in top if item["feature"] in FEATURE_MITRE_HINTS})
    return {
        "rule_id": "ai-anomaly",
        "title": f"AI: anomalous behaviour on {host_id} ({reason})",
        "severity": "high" if result["ai_score"] >= 0.8 else "medium",
        "confidence": 0.8,
        "mitre_attack": mitre,
        "event_id": event_id,
    }


def analyze_pending(now: datetime | None = None, lookback_minutes: int | None = None,
                    grace_seconds: int | None = None) -> dict[str, Any]:
    """Score every closed, not-yet-analysed window in the lookback horizon."""
    with _lock:
        detector = get_detector()
        if detector is None:
            return {"status": "model_not_trained", "model_path": str(model_path())}

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
        if not pending:
            return {"status": "ok", "model_version": detector.version, "analyzed": 0, "anomalies": 0}

        rows = [window_features(window_events) for _, _, _, window_events in pending]
        results = detector.score_many(rows)
        confidence = {str(rule.get("id")): float(rule.get("confidence", 1.0)) for rule in load_default_rules()}

        anomalies = 0
        for (host_id, start, end, window_events), features, result in zip(pending, rows, results):
            event_ids = [str(event["event_id"]) for event in window_events]
            alert = None
            if result["is_anomaly"]:
                anomalies += 1
                alert = build_anomaly_alert(host_id, result, event_ids[-1])
            save_ai_window(
                {"host_id": host_id, "window_start": _iso(start), "window_end": _iso(end),
                 "event_count": len(window_events), "features": features},
                result, event_ids, alert, confidence,
            )
        log.info("AI analysed %s windows, %s anomalies", len(pending), anomalies)
        return {"status": "ok", "model_version": detector.version, "analyzed": len(pending), "anomalies": anomalies}
