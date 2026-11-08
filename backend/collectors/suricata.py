from typing import Any

from fastapi import HTTPException

from ingestion import deterministic_event_id


def normalize_eve_record(record: dict[str, Any], collector_id: str) -> dict[str, Any]:
    raw_event_type = str(record.get("event_type") or "").strip().lower()
    if not raw_event_type or not raw_event_type.replace("_", "").isalnum():
        raise HTTPException(status_code=422, detail="Suricata EVE event_type is required")
    alert = record.get("alert") or {}
    if not isinstance(alert, dict):
        raise HTTPException(status_code=422, detail="Suricata alert field must be an object")

    event_type = "network_alert" if raw_event_type == "alert" else f"suricata_{raw_event_type}"
    severity = "info"
    if raw_event_type == "alert" and alert.get("severity") is not None:
        try:
            numeric_severity = int(alert["severity"])
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=422, detail="Suricata alert.severity must be an integer") from error
        severity = {1: "high", 2: "medium", 3: "low"}.get(numeric_severity, "info")

    host_id = str(record.get("src_ip") or record.get("host") or collector_id).strip()
    event: dict[str, Any] = {
        "event_type": event_type,
        "source": "suricata",
        "host_id": host_id,
        "severity": severity,
        "raw": {**record, "collector_id": collector_id},
        "event_id": deterministic_event_id("suricata", record),
    }
    if record.get("timestamp") is not None:
        event["timestamp"] = record["timestamp"]
    return event