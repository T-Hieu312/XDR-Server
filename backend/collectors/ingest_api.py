import json
import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from collectors.suricata import normalize_eve_record
from collectors.wazuh import normalize_alert
from ingestion import ingest_normalized_events

router = APIRouter(prefix="/api/collectors", tags=["collectors"])
MAX_BATCH_SIZE = 500
MAX_REQUEST_BYTES = 2 * 1024 * 1024


def _check_collector_key(env_name: str, supplied_key: str | None) -> None:
    expected_key = os.environ.get(env_name)
    if not expected_key:
        raise HTTPException(status_code=503, detail=f"{env_name} is not configured")
    if supplied_key is None or not secrets.compare_digest(
        supplied_key.encode("utf-8"), expected_key.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Invalid collector credentials")


def _extract_records(payload: Any, container: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = payload.get(container)
        if records is None:
            data = payload.get("data")
            records = data.get("affected_items") if isinstance(data, dict) else None
        if records is None:
            records = [payload]
    else:
        records = None

    if not isinstance(records, list) or not records:
        raise HTTPException(status_code=422, detail=f"Expected a non-empty {container} list")
    if len(records) > MAX_BATCH_SIZE:
        raise HTTPException(status_code=413, detail=f"Batch exceeds {MAX_BATCH_SIZE} records")
    if any(not isinstance(record, dict) for record in records):
        raise HTTPException(status_code=422, detail="Every collector record must be a JSON object")
    return records


async def _read_json_payload(request: Request) -> Any:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="Collector request exceeds 2 MiB")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from error
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="Collector request exceeds 2 MiB")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON") from error


@router.post("/wazuh/events")
async def ingest_wazuh_events(
    request: Request,
    x_collector_key: str | None = Header(default=None),
) -> dict[str, int]:
    _check_collector_key("XDR_WAZUH_INGEST_KEY", x_collector_key)
    payload = await _read_json_payload(request)
    records = _extract_records(payload, "alerts")
    try:
        return ingest_normalized_events([normalize_alert(record) for record in records], "wazuh")
    except ValueError as error:
        raise HTTPException(status_code=422, detail=error.args[0]) from error


@router.post("/suricata/events")
async def ingest_suricata_events(
    request: Request,
    x_collector_id: str = Header(...),
    x_collector_key: str | None = Header(default=None),
) -> dict[str, int]:
    _check_collector_key("XDR_SURICATA_INGEST_KEY", x_collector_key)
    collector_id = x_collector_id.strip()
    if not collector_id or len(collector_id) > 128:
        raise HTTPException(status_code=400, detail="X-Collector-Id must be 1-128 characters")
    payload = await _read_json_payload(request)
    records = _extract_records(payload, "events")
    try:
        return ingest_normalized_events(
            [normalize_eve_record(record, collector_id) for record in records],
            "suricata",
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=error.args[0]) from error
