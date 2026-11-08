from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class Alert(BaseModel):
    alert_id: str
    event_id: str
    incident_id: str
    rule_id: str
    title: str
    severity: str
    risk_score: int
    ai_score: float = 0.0
    mitre_attack: list[str]
    status: Literal["open", "acknowledged", "resolved"]
    created_at: datetime


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]