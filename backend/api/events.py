import os
import secrets
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import ValidationError

from database.database import list_events as fetch_events
from database.database import save_event_with_alerts
from ingestion import detect_event, load_detection_content
from api.security import require_roles
from models.event import Event

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[Event])
def list_events(
    limit: int = Query(default=100, ge=1, le=500),
    _: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    return fetch_events(limit)


@router.post("", status_code=201)
def ingest_event(
    event: Event, _: dict[str, Any] = Depends(require_roles("admin", "analyst"))
) -> dict[str, Any]:
    event_data = event.model_dump(mode="json")
    matched_rules = detect_event(event_data, *load_detection_content())
    try:
        return save_event_with_alerts(event_data, matched_rules)
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="An event with this event_id already exists") from error


@router.post("/batch")
def ingest_edr_batch(
    events: list[dict[str, Any]],
    x_agent_id: str = Header(...),
    x_agent_key: str = Header(...),
) -> dict[str, int]:
    expected_key = os.environ.get("XDR_AGENT_KEY")
    if not expected_key:
        raise HTTPException(status_code=503, detail="XDR_AGENT_KEY is not configured")
    if not secrets.compare_digest(x_agent_key, expected_key):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")
    if not x_agent_id.strip():
        raise HTTPException(status_code=400, detail="X-Agent-Id must not be empty")
    if not events:
        raise HTTPException(status_code=422, detail="Event batch must not be empty")
    if len(events) > 500:
        raise HTTPException(status_code=413, detail="Event batch exceeds 500 events")

    accepted = 0
    duplicates = 0
    rules, iocs = load_detection_content()
    for raw_event in events:
        computer = str(raw_event.get("computer") or x_agent_id)
        record_id = raw_event.get("record_id")
        event_id = str(raw_event.get("event_id") or "")
        if not event_id and record_id is not None:
            event_id = f"edr:{x_agent_id}:{computer}:{record_id}"

        event_payload: dict[str, Any] = {
            "event_type": str(raw_event.get("event_type") or "unknown"),
            "source": "edr",
            "host_id": computer,
            "severity": str(raw_event.get("severity") or "info"),
            "raw": {**raw_event, "agent_id": x_agent_id},
        }
        if event_id:
            event_payload["event_id"] = event_id
        if raw_event.get("timestamp") is not None:
            event_payload["timestamp"] = raw_event["timestamp"]

        try:
            event = Event(**event_payload)
        except ValidationError as error:
            raise HTTPException(status_code=422, detail=error.errors()) from error

        event_data = event.model_dump(mode="json")
        try:
            save_event_with_alerts(event_data, detect_event(event_data, rules, iocs))
        except sqlite3.IntegrityError as error:
            if "events.event_id" not in str(error):
                raise
            duplicates += 1
        else:
            accepted += 1

    return {"received": accepted, "duplicates": duplicates}