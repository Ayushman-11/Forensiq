"""
Response actions: request, approve, dry-run, execute and roll back containment actions.

Anyone signed in can ask. A different SOC manager or admin approves. Nothing changes a target system
until an approved request is executed with live execution switched on. See services/response_actions.py.
"""

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.database.session import get_db
from app.services import response_actions as ra

router = APIRouter()

Status = Literal["pending_approval", "approved", "executing", "succeeded", "failed", "rejected", "cancelled", "expired", "rolled_back"]


class CreateRequest(BaseModel):
    action_type: str = Field(max_length=40)
    target: str = Field(max_length=300)
    reason: str = Field(max_length=2000)
    alert_id: Optional[str] = Field(default=None, max_length=100)
    incident_id: Optional[str] = Field(default=None, max_length=100)


class NoteRequest(BaseModel):
    note: Optional[str] = Field(default=None, max_length=2000)


def _err(exc: ra.ResponseError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/capabilities")
async def capabilities(user: dict = Depends(get_current_user)):
    """What can be requested, which connectors are configured, and whether live execution is on."""
    return ra.capabilities()


@router.get("")
async def list_requests(status: Optional[Status] = Query(None), limit: int = Query(100, ge=1, le=300),
                        db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    return [ra.public(d) for d in await ra.list_requests(db, user, status, limit)]


@router.post("", status_code=201)
async def create(payload: CreateRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return ra.public(await ra.create_request(db, user, payload.action_type, payload.target, payload.reason, payload.alert_id, payload.incident_id))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.get("/{request_id}")
async def read(request_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return ra.public(await ra.get_request(db, user, request_id))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/approve")
async def approve(request_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return ra.public(await ra.approve(db, user, request_id, payload.note))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/reject")
async def reject(request_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return ra.public(await ra.reject(db, user, request_id, payload.note or ""))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/cancel")
async def cancel(request_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    try:
        return ra.public(await ra.cancel(db, user, request_id))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/dry-run")
async def dry_run(request_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Look at the target without changing it. No approval needed."""
    try:
        return ra.public(await ra.dry_run(db, user, request_id))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/execute")
async def execute(request_id: str, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Apply an approved request to the target system."""
    try:
        return ra.public(await ra.execute(db, user, request_id))
    except ra.ResponseError as exc:
        raise _err(exc)


@router.post("/{request_id}/rollback")
async def rollback(request_id: str, payload: NoteRequest, db: AsyncIOMotorDatabase = Depends(get_db), user: dict = Depends(get_current_user)):
    """Undo a succeeded action (lift isolation, re-enable user, unblock IP). SOC manager or admin."""
    try:
        return ra.public(await ra.rollback(db, user, request_id, payload.note or ""))
    except ra.ResponseError as exc:
        raise _err(exc)
