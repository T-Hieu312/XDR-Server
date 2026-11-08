import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.security import require_roles
from auth.passwords import hash_password
from database.users import create_user, list_users, update_user_access
from models.accounts import PublicUser, UserAccessUpdate, UserCreate

router = APIRouter(
    prefix="/api/users",
    tags=["users"],
)


@router.get("", response_model=list[PublicUser])
def get_users(
    _: dict[str, Any] = Depends(require_roles("admin")),
) -> list[dict[str, Any]]:
    return list_users()


@router.post("", response_model=PublicUser, status_code=201)
def add_user(
    user: UserCreate,
    _: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    password_hash, password_salt = hash_password(user.password)
    try:
        return create_user(
            user.username.strip(), password_hash, password_salt, user.role
        )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="Username already exists") from error


@router.patch("/{user_id}", response_model=PublicUser)
def change_user_access(
    user_id: str,
    update: UserAccessUpdate,
    actor: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    if actor["user_id"] == user_id and update.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    try:
        user = update_user_access(user_id, update.role, update.is_active)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
