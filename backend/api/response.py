from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.security import require_roles
from database.response import (
    claim_agent_commands,
    agent_owns_host,
    create_response_request,
    finish_agent_command,
    host_is_observed,
    list_response_requests,
    review_response_request,
)
from api.agent_auth import authenticate_agent
from models.response import (
    BlockIPRequest,
    HostResponseRequest,
    KillProcessRequest,
    ResponseRequest,
    ResponseReview,
)

router = APIRouter(
    prefix="/api/response",
    tags=["response"],
    dependencies=[Depends(require_roles("admin"))],
)
agent_router = APIRouter(prefix="/api/agent", tags=["agent response"])


class CommandResult(BaseModel):
    request_id: str
    success: bool
    result: str = Field(max_length=1000)


@agent_router.get("/commands")
def get_agent_commands(
    x_agent_id: str = Header(...),
    x_agent_key: str = Header(...),
    x_host_id: str = Header(...),
) -> dict[str, list[dict[str, object]]]:
    agent_id, host_id = x_agent_id.strip(), x_host_id.strip()
    if not agent_id or len(agent_id) > 128 or not host_id or len(host_id) > 255:
        raise HTTPException(status_code=400, detail="Invalid agent or host ID")
    authenticate_agent(agent_id, x_agent_key)
    if not agent_owns_host(agent_id, host_id):
        raise HTTPException(status_code=403, detail="Agent is not registered for this host")
    return {"commands": claim_agent_commands(agent_id, host_id)}


@agent_router.post("/commands/result")
def report_agent_command(
    result: CommandResult,
    x_agent_id: str = Header(...),
    x_agent_key: str = Header(...),
) -> dict[str, bool]:
    agent_id = x_agent_id.strip()
    authenticate_agent(agent_id, x_agent_key)
    if not finish_agent_command(result.request_id, agent_id, result.success, result.result):
        raise HTTPException(status_code=404, detail="Command execution not found or already reported")
    return {"accepted": True}


def _require_observed_host(host_id: str) -> None:
    if not host_is_observed(host_id):
        raise HTTPException(
            status_code=404,
            detail="Host has no events in XDR inventory",
        )


@router.get("/requests", response_model=list[ResponseRequest])
def get_response_requests(
    status_filter: Literal["pending", "approved", "rejected"] | None = Query(
        default=None, alias="status"
    ),
) -> list[dict[str, Any]]:
    return list_response_requests(status_filter)


@router.post("/kill-process", response_model=ResponseRequest, status_code=status.HTTP_202_ACCEPTED)
def request_kill_process(
    request: KillProcessRequest,
    requester: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    _require_observed_host(request.host_id)
    return create_response_request(
        "kill_process",
        {"host_id": request.host_id, "process_id": request.process_id},
        request.reason,
        requester["user_id"],
    )


@router.post("/block-ip", response_model=ResponseRequest, status_code=status.HTTP_202_ACCEPTED)
def request_block_ip(
    request: BlockIPRequest,
    requester: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    return create_response_request(
        "block_ip",
        {"ip_address": request.ip_address},
        request.reason,
        requester["user_id"],
    )


@router.post("/isolate-host", response_model=ResponseRequest, status_code=status.HTTP_202_ACCEPTED)
def request_isolate_host(
    request: HostResponseRequest,
    requester: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    _require_observed_host(request.host_id)
    return create_response_request(
        "isolate_host",
        {"host_id": request.host_id},
        request.reason,
        requester["user_id"],
    )


@router.post("/restore-host", response_model=ResponseRequest, status_code=status.HTTP_202_ACCEPTED)
def request_restore_host(
    request: HostResponseRequest,
    requester: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    _require_observed_host(request.host_id)
    return create_response_request(
        "isolate_host", {"host_id": request.host_id, "operation": "restore"}, request.reason, requester["user_id"]
    )


@router.patch("/requests/{request_id}", response_model=ResponseRequest)
def review_request(
    request_id: str,
    review: ResponseReview,
    reviewer: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    response_request, error = review_response_request(
        request_id,
        review.status,
        reviewer["user_id"],
        review.review_note,
    )
    if error == "not_found":
        raise HTTPException(status_code=404, detail="Response request not found")
    if error == "self_review":
        raise HTTPException(
            status_code=409,
            detail="A different administrator must review this request",
        )
    if error == "already_reviewed":
        raise HTTPException(
            status_code=409,
            detail="Response request has already been reviewed",
        )
    return response_request
