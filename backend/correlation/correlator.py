from datetime import datetime, timedelta, timezone
from typing import Any

from database.database import count_events_in_window

AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW_SECONDS = 300


def correlated_detection_rules(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect a Wazuh authentication-failure burst across persisted events."""
    if (
        event.get("source") != "wazuh"
        or event.get("event_type") != "authentication_failure"
        or not event.get("host_id")
    ):
        return []

    try:
        event_time = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        event_time = datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    event_time = event_time.astimezone(timezone.utc)
    window_start = event_time - timedelta(seconds=AUTH_FAILURE_WINDOW_SECONDS)
    previous_count = count_events_in_window(
        str(event["host_id"]),
        "authentication_failure",
        "wazuh",
        window_start.isoformat(),
        event_time.isoformat(),
    )
    if previous_count != AUTH_FAILURE_THRESHOLD - 1:
        return []
    return [{
        "id": "wazuh-auth-failure-burst",
        "name": f"{AUTH_FAILURE_THRESHOLD} authentication failures within 5 minutes",
        "severity": "high",
        "confidence": 0.9,
        "mitre_attack": ["T1110"],
    }]
