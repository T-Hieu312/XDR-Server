from datetime import datetime

from pydantic import BaseModel


class Host(BaseModel):
    host_id: str
    last_seen: datetime
    event_count: int
    open_alert_count: int