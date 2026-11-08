from datetime import datetime, timezone
from typing import Any


def normalize_event(raw: dict[str, Any], source: str) -> dict[str, Any]:
    """Map a source event into the platform's small canonical event shape."""
    return {
        "event_id": str(raw.get("event_id") or raw.get("id") or ""),
        "timestamp": str(raw.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        "event_type": str(raw.get("event_type") or raw.get("type") or "unknown"),
        "source": source,
        "host_id": str(raw.get("host_id") or raw.get("hostname") or "unknown"),
        "severity": str(raw.get("severity") or "info"),
        "raw": raw,
    }