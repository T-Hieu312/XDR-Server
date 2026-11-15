import hashlib
import json
import sqlite3
from typing import Any

from pydantic import ValidationError

from correlation.correlator import correlated_detection_rules
from database.database import save_event_with_alerts
from detection.anomaly_engine import anomaly_score
from detection.ioc_engine import load_iocs, match_iocs
from detection.rule_engine import load_default_rules, match_event
from models.event import Event


def detect_event(
    event: dict[str, Any],
    rules: list[dict[str, Any]] | None = None,
    iocs: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    matched_rules = match_event(event, rules if rules is not None else load_default_rules())
    matched_rules.extend(match_iocs(event, iocs if iocs is not None else load_iocs()))
    matched_rules.extend(correlated_detection_rules(event))
    return matched_rules


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
    rules = load_default_rules()
    iocs = load_iocs()
    for event_data in validated_events:
        try:
            save_event_with_alerts(
                event_data,
                detect_event(event_data, rules, iocs),
                anomaly_score(event_data),
            )
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
