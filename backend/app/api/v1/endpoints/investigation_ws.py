"""
WebSocket endpoint for real-time investigation pipeline streaming.
Supports secure ticket authentication, subprotocol authentication, and Bearer headers.
Prevents leaking long-lived JWTs into web proxy and access logs.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import db_config
from app.core.config import settings
from app.core.security import decode_token, TokenError
from app.core.logging import logger
from app.core.tenancy import scoped_query
from app.services.investigation_streamer import (
    investigation_stream_manager,
    reconstruct_steps_from_alert,
    json_serial,
)

router = APIRouter()


async def authenticate_ws_connection(
    websocket: WebSocket,
    token: Optional[str],
    ticket: Optional[str],
    db: AsyncIOMotorDatabase,
) -> Optional[dict]:
    """
    Validates WebSocket authentication via:
    1. Single-use ticket (via query param `ticket=` or Sec-WebSocket-Protocol `ticket-<ticket>`)
    2. Sec-WebSocket-Protocol `token-<access_token>`
    3. Authorization header `Bearer <access_token>`
    4. Fallback legacy token query parameter (deprecated)
    """
    selected_ticket = ticket

    # Check Sec-WebSocket-Protocol header for tickets or tokens
    protocols = websocket.headers.get("sec-websocket-protocol", "").split(",")
    auth_token = None

    for p in protocols:
        p = p.strip()
        if p.startswith("ticket-"):
            selected_ticket = p[7:].strip()
            break
        elif p.startswith("token-"):
            auth_token = p[6:].strip()
            break

    # 1. Authenticate via Single-Use Ticket
    if selected_ticket:
        ticket_doc = await db["ws_tickets"].find_one_and_delete({"_id": selected_ticket})
        if ticket_doc:
            # Check expiry
            if ticket_doc.get("expires_at") > datetime.now(timezone.utc):
                user = await db["users"].find_one({"_id": ticket_doc["user_id"]})
                if user and user.get("is_active", False):
                    user["id"] = str(user.get("_id"))
                    user["org_id"] = user.get("org_id", "default")
                    return user
        return None

    # 2. Authenticate via Bearer header
    if not auth_token:
        header_auth = websocket.headers.get("authorization")
        if header_auth and header_auth.lower().startswith("bearer "):
            auth_token = header_auth[7:].strip()

    # 3. Fallback to token parameter
    if not auth_token:
        auth_token = token

    if not auth_token:
        return None

    try:
        payload = decode_token(auth_token)
    except TokenError:
        return None

    if payload.get("type") != "access":
        return None

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        return None

    user["id"] = str(user.get("_id"))
    user["org_id"] = user.get("org_id", "default")
    return user


async def handle_websocket_investigation(
    websocket: WebSocket,
    alert_id: str,
    token: Optional[str] = Query(None),
    ticket: Optional[str] = Query(None),
    auto_start: bool = Query(True),
):
    """
    Unified WebSocket handler for streaming investigation events.
    """
    await websocket.accept()

    if not db_config.client:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Database unavailable")
        return

    db = db_config.client[settings.MONGO_DB_NAME]

    # Authenticate via ticket / protocol / token
    user = await authenticate_ws_connection(websocket, token, ticket, db)
    if not user:
        await websocket.send_text(json.dumps({
            "event": "error",
            "data": {"error": "Authentication failed: Invalid or expired ticket/token"}
        }))
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized")
        return

    # Check alert existence
    alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
    if not alert:
        await websocket.send_text(json.dumps({
            "event": "error",
            "data": {"error": f"Alert {alert_id} not found"}
        }))
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Alert not found")
        return

    # Register client for broadcast updates
    investigation_stream_manager.register(alert_id, websocket)

    try:
        # Acknowledge connection
        await websocket.send_text(json.dumps({
            "event": "connected",
            "data": {
                "alert_id": alert_id,
                "user": user.get("email"),
                "status": alert.get("status"),
            }
        }))

        current_status = alert.get("status", "New")

        if current_status == "Investigated" and not auto_start:
            # Reconstruct past steps
            await websocket.send_text(json.dumps({
                "event": "status",
                "data": {"status": "already_investigated", "message": "Alert has already been investigated."}
            }))
            steps = reconstruct_steps_from_alert(alert)
            for s in steps:
                await websocket.send_text(json.dumps({
                    "event": "node_complete",
                    "data": s,
                }, default=json_serial))
                await asyncio.sleep(0.05)

            await websocket.send_text(json.dumps({
                "event": "complete",
                "data": {
                    "alert_id": alert_id,
                    "verdict": alert.get("verdict"),
                    "confidence": alert.get("confidence"),
                    "recommended_actions": alert.get("recommended_actions", []),
                }
            }))
        elif auto_start and current_status != "Investigating":
            # Auto-trigger pipeline if requested
            await websocket.send_text(json.dumps({
                "event": "status",
                "data": {"status": "starting", "message": "Initiating AI graph investigation..."}
            }))
            asyncio.create_task(
                investigation_stream_manager.run_investigation(
                    alert_id=alert_id,
                    org_id=user.get("org_id", "default"),
                )
            )

        # Message receiver loop
        while True:
            raw_msg = await websocket.receive_text()
            try:
                msg = json.loads(raw_msg)
            except json.JSONDecodeError:
                continue

            command = msg.get("command")
            if command == "ping":
                await websocket.send_text(json.dumps({"event": "pong", "data": {}}))
            elif command in ("start", "reinvestigate"):
                await websocket.send_text(json.dumps({
                    "event": "status",
                    "data": {"status": "starting", "message": "Restarting investigation..."}
                }))
                asyncio.create_task(
                    investigation_stream_manager.run_investigation(
                        alert_id=alert_id,
                        org_id=user.get("org_id", "default"),
                    )
                )

    except WebSocketDisconnect:
        logger.info("ws_client_disconnected", alert_id=alert_id)
    except Exception as e:
        logger.error("ws_investigation_error", alert_id=alert_id, error=str(e))
    finally:
        investigation_stream_manager.unregister(alert_id, websocket)


@router.websocket("/{alert_id}/ws")
async def websocket_investigate_endpoint(
    websocket: WebSocket,
    alert_id: str,
    token: Optional[str] = Query(None),
    ticket: Optional[str] = Query(None),
    auto_start: bool = Query(True),
):
    """WebSocket connection route: /api/v1/alerts/{alert_id}/ws"""
    await handle_websocket_investigation(websocket, alert_id, token, ticket, auto_start)


@router.websocket("/ws/{alert_id:path}")
async def websocket_investigate_path_endpoint(
    websocket: WebSocket,
    alert_id: str,
    token: Optional[str] = Query(None),
    ticket: Optional[str] = Query(None),
    auto_start: bool = Query(True),
):
    """Alternate WebSocket connection route: /api/v1/alerts/ws/{alert_id:path}"""
    await handle_websocket_investigation(websocket, alert_id, token, ticket, auto_start)
