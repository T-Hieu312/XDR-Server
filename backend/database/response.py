import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from database.database import db_session


def _request_dict(row: sqlite3.Row) -> dict[str, Any]:
    request = dict(row)
    request["target"] = json.loads(request.pop("target_json"))
    return request


def create_response_request(
    action: str, target: dict[str, str | int], reason: str, requested_by: str
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    request_id = str(uuid4())
    with db_session() as connection:
        connection.execute(
            """INSERT INTO response_requests
            (request_id, action, target_json, reason, status, requested_by,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (
                request_id,
                action,
                json.dumps(target),
                reason,
                requested_by,
                now,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM response_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
    return _request_dict(row)


def list_response_requests(status: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM response_requests"
    parameters: tuple[str, ...] = ()
    if status is not None:
        query += " WHERE status = ?"
        parameters = (status,)
    query += " ORDER BY created_at DESC LIMIT 500"
    with db_session() as connection:
        rows = connection.execute(query, parameters).fetchall()
    requests = [_request_dict(row) for row in rows]
    for request in requests:
        request["executions"] = list_agent_executions(request["request_id"])
    return requests


def review_response_request(
    request_id: str, status: str, reviewer_id: str, review_note: str | None
) -> tuple[dict[str, Any] | None, str | None]:
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM response_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        if row is None:
            return None, "not_found"
        if row["status"] != "pending":
            return _request_dict(row), "already_reviewed"
        if row["requested_by"] == reviewer_id:
            return _request_dict(row), "self_review"
        connection.execute(
            """UPDATE response_requests
            SET status = ?, reviewed_by = ?, review_note = ?, updated_at = ?
            WHERE request_id = ? AND status = 'pending'""",
            (
                status,
                reviewer_id,
                review_note,
                datetime.now(timezone.utc).isoformat(),
                request_id,
            ),
        )
        updated = connection.execute(
            "SELECT * FROM response_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
    return _request_dict(updated), None


def host_is_observed(host_id: str) -> bool:
    with db_session() as connection:
        return connection.execute(
            "SELECT 1 FROM events WHERE host_id = ? LIMIT 1", (host_id,)
        ).fetchone() is not None


def agent_owns_host(agent_id: str, host_id: str) -> bool:
    with db_session() as connection:
        return connection.execute(
            """SELECT 1 FROM events WHERE host_id = ?
            AND json_extract(raw_json, '$.agent_id') = ? LIMIT 1""",
            (host_id, agent_id),
        ).fetchone() is not None


def claim_agent_commands(agent_id: str, host_id: str) -> list[dict[str, Any]]:
    """Claim newly approved commands for this endpoint; IP blocks are broadcast to agents."""
    now = datetime.now(timezone.utc).isoformat()
    commands: list[dict[str, Any]] = []
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """SELECT r.* FROM response_requests r
            LEFT JOIN response_executions x ON x.request_id = r.request_id AND x.agent_id = ?
            WHERE r.status = 'approved' AND x.request_id IS NULL
              AND julianday(r.updated_at) >= julianday('now', '-1 day')
              AND (r.action = 'block_ip' OR json_extract(r.target_json, '$.host_id') = ?)
            ORDER BY r.created_at LIMIT 20""",
            (agent_id, host_id),
        ).fetchall()
        for row in rows:
            connection.execute(
                """INSERT OR IGNORE INTO response_executions
                (request_id, agent_id, status, updated_at) VALUES (?, ?, 'running', ?)""",
                (row['request_id'], agent_id, now),
            )
            if connection.execute("SELECT changes()").fetchone()[0]:
                request = _request_dict(row)
                commands.append({
                    "request_id": request["request_id"],
                    "action": request["action"],
                    "target": request["target"],
                    "reason": request["reason"],
                })
    return commands


def finish_agent_command(request_id: str, agent_id: str, success: bool, result: str) -> bool:
    status = "succeeded" if success else "failed"
    with db_session() as connection:
        cursor = connection.execute(
            """UPDATE response_executions SET status = ?, result = ?, updated_at = ?
            WHERE request_id = ? AND agent_id = ? AND status = 'running'""",
            (status, result[:1000], datetime.now(timezone.utc).isoformat(), request_id, agent_id),
        )
        return cursor.rowcount == 1


def list_agent_executions(request_id: str) -> list[dict[str, Any]]:
    with db_session() as connection:
        rows = connection.execute(
            """SELECT agent_id, status, result, updated_at FROM response_executions
            WHERE request_id = ? ORDER BY updated_at""", (request_id,)
        ).fetchall()
    return [dict(row) for row in rows]
