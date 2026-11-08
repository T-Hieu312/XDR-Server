from typing import Any


def event_features(event: dict[str, Any]) -> dict[str, float]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    severity = {"info": 0.0, "low": 0.2, "medium": 0.45, "high": 0.7, "critical": 1.0}.get(str(event.get("severity", "info")).lower(), 0.0)
    event_type = str(event.get("event_type", "")).lower()
    risky_terms = ("suspicious", "malware", "failed", "brute", "powershell", "credential", "exploit")
    risky_type = float(any(term in event_type for term in risky_terms))
    numeric = 0.0
    for key in ("failed_count", "process_count", "bytes", "packet_count"):
        try:
            numeric = max(numeric, min(1.0, float(raw.get(key, 0)) / 1000.0))
        except (TypeError, ValueError):
            pass
    return {"severity": severity, "risky_type": risky_type, "volume": numeric,
            "missing_host": float(not bool(event.get("host_id") and event.get("host_id") != "unknown"))}


def anomaly_score(event: dict[str, Any]) -> float:
    """Transparent baseline score (0..1); replace with a trained model when labeled telemetry exists."""
    f = event_features(event)
    return round(min(1.0, f["severity"] * 0.35 + f["risky_type"] * 0.35 + f["volume"] * 0.2 + f["missing_host"] * 0.1), 3)
