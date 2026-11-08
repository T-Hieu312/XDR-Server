from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from api.security import require_roles
from database.database import list_incidents as fetch_incidents
from database.database import update_incident_status
from models.incident import Incident, IncidentStatusUpdate

router = APIRouter(
    prefix="/api/incidents",
    tags=["incidents"],
)


@router.get("", response_model=list[Incident])
def list_incidents(
    status: Literal["open", "acknowledged", "resolved"] | None = Query(default=None),
    _: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    return fetch_incidents(status)


@router.patch("/{incident_id}", response_model=Incident)
def change_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    _: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    incident = update_incident_status(incident_id, update.status)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident