from typing import Any

from fastapi import HTTPException

from ingestion import deterministic_event_id


def normalize_alert(record: dict[str, Any]) -> dict[str, Any]:
    rule = record.get("rule") or {}
    agent = record.get("agent") or {}
    if not isinstance(rule, dict) or not isinstance(agent, dict):
        raise HTTPException(status_code=422, detail="Wazuh rule and agent fields must be objects")
    host_id = str(agent.get("name") or agent.get("id") or "").strip()
    if not host_id:
        raise HTTPException(status_code=422, detail="Wazuh alert must include agent.name or agent.id")
    description = str(rule.get("description") or "")
    groups = rule.get("groups", [])
    group_text = " ".join(str(group) for group in groups) if isinstance(groups, list) else str(groups)
    auth_text = f"{description} {group_text}".lower().replace("-", "_").replace(" ", "_")
    event_type = (
        "authentication_failure"
        if any(
            term in auth_text
            for term in (
                "authentication_failure",
                "authentication_failed",
                "invalid_login",
                "failed_login",
            )
        )
        else "wazuh_alert"
    )
    event: dict[str, Any] = {
        "event_type": event_type,
        "source": "wazuh",
        "host_id": host_id,
        "severity": _severity_from_level(rule.get("level", 0)),
        "raw": record,
    }
    if record.get("timestamp") is not None:
        event["timestamp"] = record["timestamp"]
    event["event_id"] = (
        f"wazuh:{record['id']}"
        if record.get("id") is not None
        else deterministic_event_id("wazuh", record)
    )
    return event


def _severity_from_level(level: Any) -> str:
    try:
        numeric_level = int(level)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="Wazuh rule.level must be an integer") from error
    if numeric_level < 0 or numeric_level > 16:
        raise HTTPException(status_code=422, detail="Wazuh rule.level must be between 0 and 16")
    if numeric_level == 0:
        return "info"
    if numeric_level <= 3:
        return "low"
    if numeric_level <= 7:
        return "medium"
    if numeric_level <= 11:
        return "high"
    return "critical"