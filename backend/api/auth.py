from fastapi import APIRouter, Depends, Header, HTTPException, Response

from api.security import issue_session, require_current_user
from auth.passwords import hash_password, verify_password
from database.users import (
    delete_session,
    get_user_for_login,
    token_digest,
    update_password,
)
from models.accounts import LoginRequest, LoginResponse, PasswordUpdate, PublicUser

router = APIRouter(prefix="/api/auth", tags=["auth"])
DUMMY_PASSWORD_HASH, DUMMY_PASSWORD_SALT = hash_password(
    "not-a-real-user-password", bytes(16)
)


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest) -> LoginResponse:
    user = get_user_for_login(credentials.username)
    password_matches = verify_password(
        credentials.password,
        user["password_hash"] if user else DUMMY_PASSWORD_HASH,
        user["password_salt"] if user else DUMMY_PASSWORD_SALT,
    )
    if user is None or not user["is_active"] or not password_matches:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_at = issue_session(user["user_id"])
    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        user=PublicUser(**user),
    )


@router.get("/me", response_model=PublicUser)
def get_me(user: dict = Depends(require_current_user)) -> dict:
    return user


@router.post("/logout", status_code=204)
def logout(
    _: dict = Depends(require_current_user),
    authorization: str = Header(...),
) -> Response:
    _, _, token = authorization.partition(" ")
    delete_session(token_digest(token))
    return Response(status_code=204)


@router.post("/password", status_code=204)
def change_password(
    update: PasswordUpdate,
    user: dict = Depends(require_current_user),
) -> Response:
    stored = get_user_for_login(user["username"])
    if stored is None or not verify_password(
        update.current_password, stored["password_hash"], stored["password_salt"]
    ):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    password_hash, password_salt = hash_password(update.new_password)
    if not update_password(user["user_id"], password_hash, password_salt):
        raise HTTPException(status_code=401, detail="Account is inactive")
    return Response(status_code=204)
