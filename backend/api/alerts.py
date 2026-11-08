from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from api.security import require_roles
from database.database import list_alerts as fetch_alerts
from database.database import update_alert_status
from models.alert import Alert, AlertStatusUpdate

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
)


@router.get("", response_model=list[Alert])
def list_alerts(
    status: Literal["open", "acknowledged", "resolved"] | None = Query(default=None),
    _: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    return fetch_alerts(status)


@router.patch("/{alert_id}", response_model=Alert)
def change_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    _: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    alert = update_alert_status(alert_id, update.status)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert