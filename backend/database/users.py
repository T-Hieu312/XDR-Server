import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from database.database import db_session

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _auth_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        **_public_user(row),
        "password_hash": row["password_hash"],
        "password_salt": row["password_salt"],
    }


def create_user(
    username: str, password_hash: str, password_salt: str, role: str
) -> dict[str, Any]:
    now = _utc_now()
    user_id = str(uuid4())
    with db_session() as connection:
        connection.execute(
            """INSERT INTO users
            (user_id, username, password_hash, password_salt, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (user_id, username, password_hash, password_salt, role, now, now),
        )
        row = connection.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
    return _public_user(row)


def ensure_bootstrap_admin(username: str | None, password: str | None) -> None:
    with db_session() as connection:
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
    if not username or not password:
        raise RuntimeError(
            "No XDR users exist. Set XDR_BOOTSTRAP_ADMIN_USERNAME and "
            "XDR_BOOTSTRAP_ADMIN_PASSWORD to create the initial admin."
        )
    if (
        len(username) < 3
        or len(username) > 64
        or not username.replace("_", "").replace("-", "").isalnum()
    ):
        raise RuntimeError("Bootstrap admin username must be 3-64 letters, digits, '_' or '-'.")
    if len(password) < 12:
        raise RuntimeError("Bootstrap admin password must be at least 12 characters.")

    from auth.passwords import hash_password

    password_hash, password_salt = hash_password(password)
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count:
            return
        connection.execute(
            """INSERT INTO users
            (user_id, username, password_hash, password_salt, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'admin', 1, ?, ?)""",
            (
                str(uuid4()),
                username,
                password_hash,
                password_salt,
                _utc_now(),
                _utc_now(),
            ),
        )


def get_user_for_login(username: str) -> dict[str, Any] | None:
    with db_session() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
    return _auth_user(row) if row else None


def create_session(token_hash: str, user_id: str, expires_at: str) -> None:
    with db_session() as connection:
        connection.execute(
            "INSERT INTO user_sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, expires_at, _utc_now()),
        )


def get_session_user(token_hash: str) -> dict[str, Any] | None:
    now = _utc_now()
    with db_session() as connection:
        row = connection.execute(
            """SELECT u.* FROM user_sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1""",
            (token_hash, now),
        ).fetchone()
        connection.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (now,))
    return _public_user(row) if row else None


def delete_session(token_hash: str) -> None:
    with db_session() as connection:
        connection.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))


def list_users() -> list[dict[str, Any]]:
    with db_session() as connection:
        rows = connection.execute(
            "SELECT * FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()
    return [_public_user(row) for row in rows]


def update_user_access(
    user_id: str, role: str | None, is_active: bool | None
) -> dict[str, Any] | None:
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return None

        new_role = role if role is not None else row["role"]
        new_active = int(is_active if is_active is not None else row["is_active"])
        if row["is_active"] and row["role"] == "admin" and (
            new_role != "admin" or not new_active
        ):
            active_admins = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise ValueError("Cannot remove or deactivate the last active admin.")

        now = _utc_now()
        connection.execute(
            """UPDATE users SET role = ?, is_active = ?, updated_at = ?
            WHERE user_id = ?""",
            (new_role, new_active, now, user_id),
        )
        if not new_active or new_role != row["role"]:
            connection.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        updated = connection.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
    return _public_user(updated)


def update_password(user_id: str, password_hash: str, password_salt: str) -> bool:
    with db_session() as connection:
        cursor = connection.execute(
            """UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ?
            WHERE user_id = ? AND is_active = 1""",
            (password_hash, password_salt, _utc_now(), user_id),
        )
        if cursor.rowcount:
            connection.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        return cursor.rowcount == 1


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
