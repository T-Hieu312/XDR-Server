import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import ValidationError

from api.agent_auth import authenticate_agent
from database.database import list_events as fetch_events
from database.database import save_event_with_alerts
from detection.anomaly_engine import anomaly_score
from api.security import require_roles
from ingestion import detect_event
from models.event import Event

router = APIRouter(prefix="/api/events", tags=["events"])
MAX_EDR_BATCH_SIZE = 500
MAX_EDR_REQUEST_BYTES = 2 * 1024 * 1024
SYSMON_EVENT_TYPES = {
    1: "process_create",
    3: "network_connect",
    10: "process_access",
    11: "file_create",
    13: "registry_set",
    22: "dns_query",
}
SYSMON_TYPE_IDS = {event_type: event_id for event_id, event_type in SYSMON_EVENT_TYPES.items()}


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
    matched_rules = detect_event(event_data)
    ai_score = anomaly_score(event_data)
    try:
        return save_event_with_alerts(event_data, matched_rules, ai_score)
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="An event with this event_id already exists") from error


@router.post("/batch")
async def ingest_edr_batch(
    request: Request,
    x_agent_id: str = Header(...),
    x_agent_key: str = Header(...),
) -> dict[str, int]:
    agent_id = x_agent_id.strip()
    if not agent_id or len(agent_id) > 128:
        raise HTTPException(status_code=400, detail="X-Agent-Id must be 1-128 characters")
    authenticate_agent(agent_id, x_agent_key)

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_EDR_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="EDR request exceeds 2 MiB")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_EDR_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="EDR request exceeds 2 MiB")
    try:
        events = json.loads(bytes(body))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=422, detail="Request body must be a JSON array") from error
    if not isinstance(events, list):
        raise HTTPException(status_code=422, detail="Request body must be a JSON array")
    if not events:
        raise HTTPException(status_code=422, detail="Event batch must not be empty")
    if len(events) > MAX_EDR_BATCH_SIZE:
        raise HTTPException(status_code=413, detail=f"Event batch exceeds {MAX_EDR_BATCH_SIZE} events")

    normalized_events: list[dict[str, Any]] = []
    for raw_event in events:
        if not isinstance(raw_event, dict):
            raise HTTPException(status_code=422, detail="Every EDR event must be a JSON object")
        event_source = raw_event.get("source")
        if event_source != "sysmon":
            raise HTTPException(status_code=422, detail="EDR events must have source=sysmon")
        event_type = raw_event.get("event_type")
        sysmon_event_id = raw_event.get("sysmon_event_id")
        if sysmon_event_id is None and event_type in SYSMON_TYPE_IDS:
            # Older agents omitted the numeric ID; infer it for the supported event types.
            sysmon_event_id = SYSMON_TYPE_IDS[event_type]
        if isinstance(sysmon_event_id, bool) or not isinstance(sysmon_event_id, int) or not 1 <= sysmon_event_id <= 65535:
            raise HTTPException(status_code=422, detail="sysmon_event_id must be an integer from 1 to 65535")
        expected_type = SYSMON_EVENT_TYPES.get(sysmon_event_id, f"sysmon_{sysmon_event_id}")
        if event_type != expected_type:
            raise HTTPException(status_code=422, detail="event_type does not match sysmon_event_id")
        if not isinstance(raw_event.get("data"), dict):
            raise HTTPException(status_code=422, detail="Sysmon event data must be an object")
        record_id = raw_event.get("record_id")
        if record_id is None or not str(record_id).strip() or len(str(record_id)) > 128:
            raise HTTPException(status_code=422, detail="Sysmon record_id is required and must be at most 128 characters")
        computer = raw_event.get("computer") or agent_id
        if not isinstance(computer, str) or not computer.strip() or len(computer) > 255:
            raise HTTPException(status_code=422, detail="Sysmon computer must be 1-255 characters")
        record_id = raw_event.get("record_id")
        event_payload: dict[str, Any] = {
            "event_type": event_type,
            "source": "edr",
            "host_id": computer,
            "severity": "info",
            "raw": {**raw_event, "sysmon_event_id": sysmon_event_id, "agent_id": agent_id},
            "event_id": f"edr:{agent_id}:{computer}:{record_id}",
        }
        if raw_event.get("timestamp") is not None:
            event_payload["timestamp"] = raw_event["timestamp"]
        try:
            event = Event(**event_payload)
        except ValidationError as error:
            raise HTTPException(status_code=422, detail=error.errors()) from error
        normalized_events.append(event.model_dump(mode="json"))

    accepted = 0
    duplicates = 0
    for event_data in normalized_events:
        try:
            save_event_with_alerts(
                event_data,
                detect_event(event_data),
                anomaly_score(event_data),
            )
        except sqlite3.IntegrityError as error:
            if "events.event_id" not in str(error):
                raise
            duplicates += 1
        else:
            accepted += 1

    return {"received": accepted, "duplicates": duplicates}
