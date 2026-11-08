import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException

from database.users import get_session_user, token_digest

SESSION_DURATION = timedelta(hours=8)


def issue_session(user_id: str) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + SESSION_DURATION
    from database.users import create_session

    create_session(token_digest(token), user_id, expires_at.isoformat())
    return token, expires_at


def require_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scheme, separator, token = (authorization or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing account credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_session_user(token_digest(token))
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(*roles: str) -> Callable[..., dict[str, Any]]:
    def role_dependency(
        user: dict[str, Any] = Depends(require_current_user),
    ) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_dependency

