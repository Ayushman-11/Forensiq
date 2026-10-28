"""
WebSocket endpoint for real-time investigation pipeline streaming.
Supports token authentication via query parameter or handshake message,
interactive commands (start, reinvestigate, ping), and pub/sub push updates.
"""

import asyncio
import json
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import db_config
from app.core.config import settings
from app.core.security import decode_token, TokenError
from app.core.logging import logger
from app.core.tenancy import scoped_query, tenant_id
from app.services.investigation_streamer import (
    investigation_stream_manager,
    reconstruct_steps_from_alert,
    serialize_data,
    json_serial,
)

router = APIRouter()


async def authenticate_ws_connection(websocket: WebSocket, token: Optional[str], db: AsyncIOMotorDatabase) -> Optional[dict]:
    """
    Validates token from query parameter, headers, or initial auth message.
    Returns the user document if valid, else None.
    """
    # 1. Check query parameter
    auth_token = token

    # 2. Check Authorization header
    if not auth_token:
        header_auth = websocket.headers.get("authorization")
        if header_auth and header_auth.lower().startswith("bearer "):
            auth_token = header_auth[7:].strip()

    # 3. Check Sec-WebSocket-Protocol header
    if not auth_token:
        protocols = websocket.headers.get("sec-websocket-protocol", "").split(",")
        for p in protocols:
            p = p.strip()
            if p.startswith("token-"):
                auth_token = p[6:].strip()
                break

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

    return user



async def handle_websocket_investigation(
    websocket: WebSocket,
    alert_id: str,
    token: Optional[str] = Query(None),
    auto_start: bool = Query(False),
):
    """
    Unified WebSocket handler for streaming investigation events.
    Defaults to observe-only (auto_start=False) to prevent accidental compute & LLM cost.
    """
    await websocket.accept()

    if not db_config.client:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Database unavailable")
        return

    db = db_config.client[settings.MONGO_DB_NAME]

    # Authenticate
    user = await authenticate_ws_connection(websocket, token, db)
    if not user:
        await websocket.send_text(json.dumps({
            "event": "error",
            "data": {"error": "Authentication failed: Invalid or missing token"}
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
                    "status": "complete",
                    "message": "Loaded existing investigation results",
                    "alert": serialize_data(alert),
                }
            }, default=json_serial))

        elif current_status == "Investigating":
            # Replay any in-flight steps currently buffered or persisted in DB
            await websocket.send_text(json.dumps({
                "event": "status",
                "data": {"status": "in_progress", "message": "Investigation is currently running."}
            }))
            history = await investigation_stream_manager.get_persisted_history(alert_id, db)
            for historical_event in history:
                await websocket.send_text(json.dumps(historical_event, default=json_serial))

        elif auto_start:
            # Run the streaming investigation directly if auto_start was explicitly requested
            async for _ in investigation_stream_manager.run_pipeline_stream(
                alert_id=alert_id,
                alert=alert,
                db=db,
                org_id=tenant_id(user),
            ):
                pass  # run_pipeline_stream broadcasts each event to all subscribers including this websocket

        else:
            # Observe-only mode: WebSocket does not spend compute automatically
            await websocket.send_text(json.dumps({
                "event": "status",
                "data": {"status": "ready", "message": "Alert ready. Start investigation via POST /investigate or start command."}
            }))

        # Message receiver loop for client interaction (heartbeat ping, reinvestigate command, etc.)
        while True:
            raw_text = await websocket.receive_text()
            try:
                cmd = json.loads(raw_text)
            except Exception:
                continue

            action = cmd.get("action")

            if action == "ping":
                await websocket.send_text(json.dumps({"event": "pong", "data": {}}))

            elif action in ("start", "reinvestigate"):
                # Fetch fresh alert state
                fresh_alert = await db["alerts"].find_one(scoped_query(user, {"_id": alert_id}))
                if fresh_alert:
                    async for _ in investigation_stream_manager.run_pipeline_stream(
                        alert_id=alert_id,
                        alert=fresh_alert,
                        db=db,
                        org_id=tenant_id(user),
                    ):
                        pass

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
    auto_start: bool = Query(False),
):
    """WebSocket connection route: /api/v1/alerts/{alert_id}/ws"""
    await handle_websocket_investigation(websocket, alert_id, token, auto_start)


@router.websocket("/ws/{alert_id:path}")
async def websocket_investigate_path_endpoint(
    websocket: WebSocket,
    alert_id: str,
    token: Optional[str] = Query(None),
    auto_start: bool = Query(False),
):
    """Alternate WebSocket connection route: /api/v1/alerts/ws/{alert_id:path}"""
    await handle_websocket_investigation(websocket, alert_id, token, auto_start)
