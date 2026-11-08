from fastapi import APIRouter, Depends

from api.security import require_roles
from database.database import list_hosts as fetch_hosts
from models.host import Host

router = APIRouter(
    prefix="/api/hosts",
    tags=["hosts"],
)


@router.get("", response_model=list[Host])
def list_hosts(
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, str | int]]:
    return fetch_hosts()