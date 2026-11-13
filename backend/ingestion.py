import hashlib
import json
import sqlite3
from typing import Any

from pydantic import ValidationError

from database.database import save_event_with_alerts
from detection.ioc_engine import load_iocs, match_iocs
from detection.rule_engine import load_default_rules, match_event
from models.event import Event


def load_detection_content() -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    return load_default_rules(), load_iocs()


def detect_event(
    event_data: dict[str, Any], rules: list[dict[str, Any]], iocs: dict[str, set[str]]
) -> list[dict[str, Any]]:
    """Per-event detection: rule matches plus IOC matches.

    AI scoring is not done here: the model scores whole host/time windows
    after they close (ai.analyzer) and then enriches these alerts' ai_score.
    """
    return match_event(event_data, rules) + match_iocs(event_data, iocs)


def ingest_normalized_events(events: list[dict[str, Any]], source: str) -> dict[str, int]:
    validated_events: list[dict[str, Any]] = []
    for event_payload in events:
        try:
            event = Event(**event_payload)
        except ValidationError as error:
            raise ValueError(error.errors(include_context=False)) from error
        event_data = event.model_dump(mode="json")
        if event_data["source"] != source:
            raise ValueError(f"Expected {source} source events")
        validated_events.append(event_data)

    accepted = 0
    duplicates = 0
    rules, iocs = load_detection_content()
    for event_data in validated_events:
        try:
            save_event_with_alerts(event_data, detect_event(event_data, rules, iocs))
        except sqlite3.IntegrityError as error:
            if "events.event_id" not in str(error):
                raise
            duplicates += 1
        else:
            accepted += 1
    return {"received": accepted, "duplicates": duplicates}


def deterministic_event_id(source: str, payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"{source}:{digest}"
