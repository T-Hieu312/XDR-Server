import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ResponseAction = Literal["kill_process", "block_ip", "isolate_host"]
ResponseStatus = Literal["pending", "approved", "rejected"]


class HostResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=500)


class KillProcessRequest(HostResponseRequest):
    process_id: int = Field(gt=0, le=2**32 - 1)


class BlockIPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip_address: str
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from error
        if address.is_multicast or address.is_unspecified:
            raise ValueError("Multicast and unspecified addresses cannot be blocked")
        return str(address)


class ResponseReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["approved", "rejected"]
    review_note: str | None = Field(default=None, max_length=500)


class ResponseRequest(BaseModel):
    request_id: str
    action: ResponseAction
    target: dict[str, str | int]
    reason: str
    status: ResponseStatus
    requested_by: str
    reviewed_by: str | None
    review_note: str | None
    created_at: datetime
    updated_at: datetime
