from typing import Any


def event_features(event: dict[str, Any]) -> dict[str, float]:
    severity_weights = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
    return {
        "severity_weight": severity_weights.get(str(event.get("severity", "info")).lower(), 0.0),
        "has_host": float(bool(event.get("host_id"))),
    }