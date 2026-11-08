from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Incident(BaseModel):
    incident_id: str
    title: str
    host_id: str
    status: Literal["open", "acknowledged", "resolved"]
    severity: str
    alert_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]