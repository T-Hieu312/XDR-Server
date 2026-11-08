from collections import defaultdict
from typing import Any


def group_by_host(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group normalized events by host for later correlation rules."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event.get("host_id", "unknown"))].append(event)
    return dict(grouped)