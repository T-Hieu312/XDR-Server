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
    return [_request_dict(row) for row in rows]


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
