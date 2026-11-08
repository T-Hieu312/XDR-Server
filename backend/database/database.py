import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def get_connection() -> sqlite3.Connection:
    database_path = Path(os.environ.get("XDR_DATABASE_PATH", "data/xdr.sqlite3"))
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    connection = get_connection()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db() -> None:
    with db_session() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                host_id TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                host_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL REFERENCES events(event_id),
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ai_score REAL NOT NULL DEFAULT 0,
                mitre_attack_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS response_requests (
                request_id TEXT PRIMARY KEY,
                action TEXT NOT NULL CHECK (action IN ('kill_process', 'block_ip', 'isolate_host')),
                target_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
                requested_by TEXT NOT NULL REFERENCES users(user_id),
                reviewed_by TEXT REFERENCES users(user_id),
                review_note TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )


    

# SQLite CREATE TABLE IF NOT EXISTS does not update existing databases.
        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")}
        if "ai_score" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN ai_score REAL NOT NULL DEFAULT 0")

def _event_dict(row: sqlite3.Row) -> dict[str, Any]:
    event = dict(row)
    event["raw"] = json.loads(event.pop("raw_json"))
    return event


def _alert_dict(row: sqlite3.Row) -> dict[str, Any]:
    alert = dict(row)
    alert["mitre_attack"] = json.loads(alert.pop("mitre_attack_json"))
    return alert


def _incident_dict(row: sqlite3.Row, alert_ids: list[str]) -> dict[str, Any]:
    incident = dict(row)
    incident["alert_ids"] = alert_ids
    return incident


def save_event_with_alerts(
    event: dict[str, Any], matched_rules: list[dict[str, Any]], ai_score: float = 0.0
) -> dict[str, Any]:
    from risk.risk_engine import calculate_risk

    event_time = event["timestamp"]
    now = datetime.now(timezone.utc).isoformat()
    alerts: list[dict[str, Any]] = []
    incident_id: str | None = None

    with db_session() as connection:
        connection.execute(
            """INSERT INTO events
            (event_id, timestamp, event_type, source, host_id, severity, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event["event_id"],
                event_time,
                event["event_type"],
                event["source"],
                event["host_id"],
                event["severity"],
                json.dumps(event["raw"]),
            ),
        )

        for rule in matched_rules:
            severity = str(rule.get("severity", event["severity"])).lower()
            if incident_id is None:
                existing = connection.execute(
                    """SELECT incident_id, severity FROM incidents
                    WHERE host_id = ? AND status != 'resolved'
                    ORDER BY created_at DESC LIMIT 1""",
                    (event["host_id"],),
                ).fetchone()
                if existing:
                    incident_id = existing["incident_id"]
                    current_severity = existing["severity"]
                    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(current_severity, 0):
                        connection.execute(
                            "UPDATE incidents SET severity = ?, updated_at = ? WHERE incident_id = ?",
                            (severity, now, incident_id),
                        )
                else:
                    incident_id = str(uuid4())
                    connection.execute(
                        """INSERT INTO incidents
                        (incident_id, title, host_id, status, severity, created_at, updated_at)
                        VALUES (?, ?, ?, 'open', ?, ?, ?)""",
                        (
                            incident_id,
                            f"Security activity on {event['host_id']}",
                            event["host_id"],
                            severity,
                            now,
                            now,
                        ),
                    )

            alert = {
                "alert_id": str(uuid4()),
                "event_id": event["event_id"],
                "incident_id": incident_id,
                "rule_id": str(rule.get("id", "unnamed-rule")),
                "title": str(rule.get("name", rule.get("id", "Detection rule matched"))),
                "severity": severity,
                "risk_score": calculate_risk(severity, float(rule.get("confidence", 1.0)), ai_score),
                "ai_score": ai_score,
                "mitre_attack": rule.get("mitre_attack", []),
                "status": "open",
                "created_at": now,
            }
            connection.execute(
                """INSERT INTO alerts
                (alert_id, event_id, incident_id, rule_id, title, severity, risk_score, ai_score,
                 mitre_attack_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert["alert_id"],
                    alert["event_id"],
                    alert["incident_id"],
                    alert["rule_id"],
                    alert["title"],
                    alert["severity"],
                    alert["risk_score"],
                    alert["ai_score"],
                    json.dumps(alert["mitre_attack"]),
                    alert["status"],
                    alert["created_at"],
                ),
            )
            alerts.append(alert)

    return {"event": event, "alerts": alerts, "incident_id": incident_id}


def list_events(limit: int = 100) -> list[dict[str, Any]]:
    with db_session() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_event_dict(row) for row in rows]


def list_alerts(status: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM alerts"
    parameters: tuple[str, ...] = ()
    if status:
        query += " WHERE status = ?"
        parameters = (status,)
    query += " ORDER BY created_at DESC"
    with db_session() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_alert_dict(row) for row in rows]


def update_alert_status(alert_id: str, status: str) -> dict[str, Any] | None:
    with db_session() as connection:
        row = connection.execute(
            "SELECT incident_id FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        connection.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
        incident_id = row["incident_id"]
        if status == "resolved":
            remaining = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE incident_id = ? AND status != 'resolved'",
                (incident_id,),
            ).fetchone()[0]
            if remaining == 0:
                connection.execute(
                    "UPDATE incidents SET status = 'resolved', updated_at = ? WHERE incident_id = ?",
                    (datetime.now(timezone.utc).isoformat(), incident_id),
                )
        elif status == "open":
            connection.execute(
                "UPDATE incidents SET status = 'open', updated_at = ? WHERE incident_id = ?",
                (datetime.now(timezone.utc).isoformat(), incident_id),
            )
        updated = connection.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    return _alert_dict(updated)


def list_incidents(status: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM incidents"
    parameters: tuple[str, ...] = ()
    if status:
        query += " WHERE status = ?"
        parameters = (status,)
    query += " ORDER BY updated_at DESC"
    with db_session() as connection:
        rows = connection.execute(query, parameters).fetchall()
        incidents = []
        for row in rows:
            alerts = connection.execute(
                "SELECT alert_id FROM alerts WHERE incident_id = ? ORDER BY created_at",
                (row["incident_id"],),
            ).fetchall()
            incidents.append(_incident_dict(row, [alert["alert_id"] for alert in alerts]))
    return incidents


def update_incident_status(incident_id: str, status: str) -> dict[str, Any] | None:
    with db_session() as connection:
        cursor = connection.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
            (status, datetime.now(timezone.utc).isoformat(), incident_id),
        )
        if cursor.rowcount == 0:
            return None
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        alerts = connection.execute(
            "SELECT alert_id FROM alerts WHERE incident_id = ? ORDER BY created_at",
            (incident_id,),
        ).fetchall()
    return _incident_dict(row, [alert["alert_id"] for alert in alerts])


def list_hosts() -> list[dict[str, Any]]:
    with db_session() as connection:
        rows = connection.execute(
            """SELECT e.host_id, MAX(e.timestamp) AS last_seen,
            COUNT(DISTINCT e.event_id) AS event_count,
            (SELECT COUNT(*) FROM alerts a JOIN events ae ON ae.event_id = a.event_id
             WHERE ae.host_id = e.host_id AND a.status != 'resolved') AS open_alert_count
            FROM events e GROUP BY e.host_id ORDER BY last_seen DESC"""
        ).fetchall()
    return [dict(row) for row in rows]