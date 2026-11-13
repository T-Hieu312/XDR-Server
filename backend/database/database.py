import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def get_database_path() -> Path:
    return Path(os.environ.get("XDR_DATABASE_PATH", "data/xdr.sqlite3"))


def get_connection() -> sqlite3.Connection:
    database_path = get_database_path()
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


        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_windows (
                host_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                features_json TEXT NOT NULL,
                ai_score REAL NOT NULL,
                raw_score REAL NOT NULL,
                is_anomaly INTEGER NOT NULL,
                top_features_json TEXT NOT NULL,
                model_version TEXT NOT NULL,
                alert_id TEXT,
                analyzed_at TEXT NOT NULL,
                PRIMARY KEY (host_id, window_start)
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")

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
                incident_id = _get_or_create_incident(connection, event["host_id"], severity, now)

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
            _insert_alert(connection, alert)
            alerts.append(alert)

    return {"event": event, "alerts": alerts, "incident_id": incident_id}


def _get_or_create_incident(connection: sqlite3.Connection, host_id: str, severity: str, now: str) -> str:
    """Attach to the host's latest unresolved incident, raising its severity if needed."""
    existing = connection.execute(
        """SELECT incident_id, severity FROM incidents
        WHERE host_id = ? AND status != 'resolved'
        ORDER BY created_at DESC LIMIT 1""",
        (host_id,),
    ).fetchone()
    if existing:
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing["severity"], 0):
            connection.execute(
                "UPDATE incidents SET severity = ?, updated_at = ? WHERE incident_id = ?",
                (severity, now, existing["incident_id"]),
            )
        return existing["incident_id"]
    incident_id = str(uuid4())
    connection.execute(
        """INSERT INTO incidents
        (incident_id, title, host_id, status, severity, created_at, updated_at)
        VALUES (?, ?, ?, 'open', ?, ?, ?)""",
        (incident_id, f"Security activity on {host_id}", host_id, severity, now, now),
    )
    return incident_id


def _insert_alert(connection: sqlite3.Connection, alert: dict[str, Any]) -> None:
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


def analyzed_window_keys(since: str) -> set[tuple[str, str]]:
    with db_session() as connection:
        rows = connection.execute(
            "SELECT host_id, window_start FROM ai_windows WHERE window_start >= ?", (since,)
        ).fetchall()
    return {(row["host_id"], row["window_start"]) for row in rows}


def save_ai_window(
    window: dict[str, Any],
    result: dict[str, Any],
    window_event_ids: list[str],
    anomaly_alert: dict[str, Any] | None,
    rule_confidence: dict[str, float],
) -> dict[str, Any]:
    """Store one scored window, enrich rule alerts in it, and optionally raise an AI alert.

    ``anomaly_alert`` holds rule_id/title/severity/mitre_attack/event_id for the AI alert.
    """
    from risk.risk_engine import calculate_risk

    now = datetime.now(timezone.utc).isoformat()
    ai_score = float(result["ai_score"])
    alert_id = None
    enriched = 0

    with db_session() as connection:
        # Enrich rule alerts raised by events of this window with the window's AI score.
        if window_event_ids:
            placeholders = ",".join("?" for _ in window_event_ids)
            rows = connection.execute(
                f"""SELECT alert_id, rule_id, severity, ai_score FROM alerts
                WHERE event_id IN ({placeholders})""",
                window_event_ids,
            ).fetchall()
            for row in rows:
                new_ai_score = max(float(row["ai_score"]), ai_score)
                connection.execute(
                    "UPDATE alerts SET ai_score = ?, risk_score = ? WHERE alert_id = ?",
                    (
                        new_ai_score,
                        calculate_risk(row["severity"], rule_confidence.get(row["rule_id"], 1.0), new_ai_score),
                        row["alert_id"],
                    ),
                )
                enriched += 1

        if anomaly_alert is not None:
            severity = anomaly_alert["severity"]
            incident_id = _get_or_create_incident(connection, window["host_id"], severity, now)
            alert_id = str(uuid4())
            _insert_alert(connection, {
                "alert_id": alert_id,
                "event_id": anomaly_alert["event_id"],
                "incident_id": incident_id,
                "rule_id": anomaly_alert["rule_id"],
                "title": anomaly_alert["title"],
                "severity": severity,
                "risk_score": calculate_risk(severity, anomaly_alert.get("confidence", 1.0), ai_score),
                "ai_score": ai_score,
                "mitre_attack": anomaly_alert["mitre_attack"],
                "status": "open",
                "created_at": now,
            })

        connection.execute(
            """INSERT OR REPLACE INTO ai_windows
            (host_id, window_start, window_end, event_count, features_json, ai_score, raw_score,
             is_anomaly, top_features_json, model_version, alert_id, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                window["host_id"],
                window["window_start"],
                window["window_end"],
                window["event_count"],
                json.dumps(window["features"]),
                ai_score,
                float(result["raw_score"]),
                int(bool(result["is_anomaly"])),
                json.dumps(result["top_features"]),
                result["model_version"],
                alert_id,
                now,
            ),
        )
    return {"alert_id": alert_id, "enriched_alerts": enriched}


def list_ai_windows(host_id: str | None = None, anomalies_only: bool = False,
                    limit: int = 100) -> list[dict[str, Any]]:
    query = "SELECT * FROM ai_windows WHERE 1=1"
    params: list[Any] = []
    if host_id:
        query += " AND host_id = ?"
        params.append(host_id)
    if anomalies_only:
        query += " AND is_anomaly = 1"
    query += " ORDER BY window_start DESC LIMIT ?"
    params.append(limit)
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    windows = []
    for row in rows:
        window = dict(row)
        window["features"] = json.loads(window.pop("features_json"))
        window["top_features"] = json.loads(window.pop("top_features_json"))
        window["is_anomaly"] = bool(window["is_anomaly"])
        windows.append(window)
    return windows


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