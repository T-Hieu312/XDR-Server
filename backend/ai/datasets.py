"""Load events for training/evaluation into the server's canonical event shape.

Supported inputs:
- the XDR SQLite database (events collected in production/lab),
- JSON / JSONL / ZIP files containing any of:
  * server events            {"host_id", "event_type", "raw", ...}
  * EDR agent events          {"computer", "event_type", "data", ...} (spool.jsonl)
  * Get-WinEvent export       {"Computer", "Channel", "EventId", "EventData"}
  * OTRF Security-Datasets    {"Hostname", "Channel", "EventID", <flat Sysmon fields>}

Raw Windows records are filtered exactly like the EDR agent does (same Sysmon
event IDs, Event 10 only for lsass) so offline data matches what the server sees.
"""
from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any, Iterable, Iterator

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
# Must match EDR-Agent sysmon_collector.EVENT_TYPE and config collector.event_ids.
SYSMON_EVENT_TYPES = {
    1: "process_create",
    3: "network_connect",
    10: "process_access",
    11: "file_create",
    13: "registry_set",
    22: "dns_query",
}
SECURITY_EVENT_TYPES = {4625: "authentication_failure"}
METADATA_FIELDS = {
    "@timestamp", "@version", "Channel", "EventID", "EventId", "Hostname", "Computer",
    "Keywords", "Level", "Message", "Opcode", "OpcodeValue", "ProviderGuid", "SourceName",
    "Task", "TimeCreated", "EventTime", "EventType", "ExecutionProcessID", "ThreadID",
    "RecordNumber", "EventRecordID", "Severity", "SeverityValue", "Version", "host", "port",
    "tags", "SourceModuleName", "SourceModuleType", "EventReceivedTime", "Category",
    "AccountName", "AccountType", "Domain", "UserID",
}


def _read_text_records(text: str) -> list[dict[str, Any]]:
    text = text.strip().lstrip("﻿")
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return data if isinstance(data, list) else [data]


def read_records(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".zip":
        records: list[dict[str, Any]] = []
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.lower().endswith((".json", ".jsonl")):
                    records.extend(_read_text_records(archive.read(name).decode("utf-8-sig")))
        return records
    return _read_text_records(path.read_text(encoding="utf-8-sig"))


def _from_windows_record(record: dict[str, Any], data: dict[str, Any], host: Any,
                         timestamp: Any, channel: str, event_id: int) -> dict[str, Any] | None:
    if channel.lower() == SYSMON_CHANNEL:
        event_type = SYSMON_EVENT_TYPES.get(event_id)
        if event_type == "process_access" and not str(data.get("TargetImage") or "").lower().endswith("\\lsass.exe"):
            return None  # EDR agent keep_event_ids_when: 10 -> lsass only
    elif channel.lower() == "security":
        event_type = SECURITY_EVENT_TYPES.get(event_id)
    else:
        event_type = None
    if event_type is None or not host or not timestamp:
        return None
    return {
        "event_type": event_type,
        "source": "edr" if channel.lower() == SYSMON_CHANNEL else "wazuh",
        "host_id": str(host),
        "timestamp": timestamp,
        "severity": "info",
        "raw": {"source": "dataset", "sysmon_event_id": event_id, "event_type": event_type, "data": data},
    }


def to_server_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one record of any supported format; return None if it is not used."""
    if "host_id" in record and "raw" in record:
        return record
    if "computer" in record and isinstance(record.get("data"), dict):
        return {
            "event_type": str(record.get("event_type") or "unknown"),
            "source": "edr",
            "host_id": str(record["computer"]),
            "timestamp": record.get("timestamp"),
            "severity": str(record.get("severity") or "info"),
            "raw": record,
        }
    if isinstance(record.get("EventData"), dict):
        return _from_windows_record(record, record["EventData"], record.get("Computer"),
                                    record.get("TimeCreated"), str(record.get("Channel") or ""),
                                    int(record.get("EventId") or record.get("EventID") or 0))
    if "EventID" in record and "Channel" in record:
        data = {key: value for key, value in record.items() if key not in METADATA_FIELDS}
        return _from_windows_record(record, data, record.get("Hostname") or record.get("Computer"),
                                    record.get("@timestamp") or record.get("TimeCreated"),
                                    str(record["Channel"]), int(record["EventID"]))
    return None


def load_file(path: str | Path) -> list[dict[str, Any]]:
    events = (to_server_event(record) for record in read_records(path) if isinstance(record, dict))
    return [event for event in events if event is not None]


def load_files(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        events.extend(load_file(path))
    return events


def iter_db_events(db_path: str | Path, since: str | None = None, until: str | None = None,
                   hosts: list[str] | None = None) -> Iterator[dict[str, Any]]:
    """Yield stored events. ``since``/``until`` are ISO timestamps compared as stored text."""
    query = "SELECT event_id, timestamp, event_type, source, host_id, severity, raw_json FROM events WHERE 1=1"
    params: list[Any] = []
    if since:
        query += " AND timestamp >= ?"
        params.append(since)
    if until:
        query += " AND timestamp < ?"
        params.append(until)
    if hosts:
        query += f" AND host_id IN ({','.join('?' for _ in hosts)})"
        params.extend(hosts)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        for row in connection.execute(query, params):
            event = dict(row)
            event["raw"] = json.loads(event.pop("raw_json"))
            yield event
    finally:
        connection.close()
