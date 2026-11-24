"""POST /api/agent/enrollment/redeem - the Windows agent trades a one-time code for
its own endpoint credential. No login and no shared key: possession of a valid,
unexpired, unrevoked code for an APPROVED request is the credential. Everything
(claim, request binding, endpoint creation) is one transaction."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.security.client_ip import get_client_ip
from app.services import enrollment_service

router = APIRouter(prefix="/api/agent/enrollment", tags=["agent-enrollment"])


class RedeemRequest(BaseModel):
    # NOTE: no scope / user / organization fields on purpose - those come from the
    # approved request on the server, never from the caller.
    code: str = Field(min_length=1, max_length=512)
    display_name: str | None = Field(default=None, max_length=200)
    operating_system: str | None = Field(default=None, max_length=200)
    agent_version: str | None = Field(default=None, max_length=50)
    endpoint_id: str | None = Field(default=None, max_length=64)


@router.post("/redeem")
def redeem(body: RedeemRequest, request: Request, session: Session = Depends(get_db)):
    return enrollment_service.redeem(
        session,
        code=body.code,
        display_name=body.display_name,
        operating_system=body.operating_system,
        agent_version=body.agent_version,
        endpoint_id=body.endpoint_id,
        ip=get_client_ip(request),
    )
