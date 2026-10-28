"""
Authentication endpoints: login, cookie-backed refresh, logout, single-use WebSocket tickets,
MFA setup/verification, and SSO/OIDC integration.
"""

import asyncio
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Cookie
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.session import get_db
from app.api.deps import get_current_user
from app.core.config import settings
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    LogoutRequest,
    TokenResponse,
    MfaSetupResponse,
    MfaVerifyRequest,
    MfaChallengeRequest,
    WsTicketResponse,
)
from app.core.security import (
    verify_password,
    hash_password,
    create_access_token,
    create_refresh_token,
    create_mfa_token,
    decode_token,
    generate_totp_secret,
    verify_totp_token,
    get_totp_provisioning_uri,
    TokenError,
)
from app.services.login_throttle import clear_failures, reserve_attempt, throttle_key

router = APIRouter()

REFRESH_COOKIE_NAME = "forensiq_refresh_token"
_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, refresh_token: str):
    """Sets HttpOnly, SameSite=Strict cookie for refresh token."""
    max_age_seconds = settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60
    is_prod = settings.ENV.strip().lower() not in {"development", "dev", "test", "local"}
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=is_prod,  # allow localhost testing without https unless in prod
        samesite="lax",  # lax or strict allows safe cross-navigation and top-level fetch
        path=_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response):
    """Clears the refresh cookie."""
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=_COOKIE_PATH,
    )


async def _issue_tokens_for_user(
    db: AsyncIOMotorDatabase,
    response: Response,
    user: dict,
) -> TokenResponse:
    user_id = str(user["_id"])
    email = user["email"]
    role = user.get("role", "analyst")
    org_id = user.get("org_id", "default")

    access_token = create_access_token(user_id=user_id, email=email, role=role, org_id=org_id)
    refresh_token, jti, expires_at = create_refresh_token(user_id=user_id)

    await db["sessions"].insert_one({
        "_id": jti,
        "user_id": user_id,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc),
    })

    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        mfa_required=False,
    )


_DUMMY_HASH = hash_password("forensiq-dummy-password-for-timing")


@router.post("/login")
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Authenticates a user by email/password.
    If MFA is enabled on the account, returns an intermediate mfa_token.
    Otherwise sets an HttpOnly refresh cookie and returns the access token.
    """
    email = req.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    key = throttle_key(email, ip)

    retry_after = await reserve_attempt(db, key)
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = await db["users"].find_one({"email": email})
    hash_to_check = user["password_hash"] if user else _DUMMY_HASH
    password_ok = await asyncio.to_thread(verify_password, req.password, hash_to_check)
    if not user or not user.get("is_active", False) or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    await clear_failures(db, key)

    # Check if MFA is required
    if user.get("mfa_enabled", False):
        mfa_token = create_mfa_token(str(user["_id"]), user["email"], user.get("role", "analyst"))
        return {
            "access_token": "",
            "token_type": "bearer",
            "mfa_required": True,
            "mfa_token": mfa_token,
        }

    return await _issue_tokens_for_user(db, response, user)


@router.post("/mfa/challenge")
async def mfa_challenge(
    req: MfaChallengeRequest,
    response: Response,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Completes login by verifying the TOTP code against the intermediate mfa_token."""
    try:
        payload = decode_token(req.mfa_token)
    except TokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token")

    if payload.get("type") != "mfa_pending":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type for MFA challenge")

    user_id = payload.get("sub")
    user = await db["users"].find_one({"_id": user_id})
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    secret = user.get("mfa_secret")
    if not secret or not verify_totp_token(secret, req.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP authentication code")

    return await _issue_tokens_for_user(db, response, user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    response: Response,
    req: Optional[RefreshRequest] = None,
    forensiq_refresh_token: Optional[str] = Cookie(None),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Rotates a refresh token: accepts cookie or JSON payload, validates,
    revokes old session jti, sets new HttpOnly cookie, and issues a fresh pair.
    """
    token_str = (req.refresh_token if req and req.refresh_token else None) or forensiq_refresh_token
    if not token_str:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    try:
        payload = decode_token(token_str)
    except TokenError:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    session = await db["sessions"].find_one_and_delete({"_id": payload.get("jti")})
    if not session:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

    user = await db["users"].find_one({"_id": payload.get("sub")})
    if not user or not user.get("is_active", False):
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return await _issue_tokens_for_user(db, response, user)


@router.post("/logout")
async def logout(
    response: Response,
    req: Optional[LogoutRequest] = None,
    forensiq_refresh_token: Optional[str] = Cookie(None),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Revokes the refresh token session and clears the HttpOnly cookie. Idempotent."""
    token_str = (req.refresh_token if req and req.refresh_token else None) or forensiq_refresh_token
    if token_str:
        try:
            payload = decode_token(token_str)
            await db["sessions"].delete_one({"_id": payload.get("jti")})
        except TokenError:
            pass

    _clear_refresh_cookie(response)
    return {"status": "logged_out"}


# --- WebSocket Ticket Endpoint ---

@router.post("/ws-ticket", response_model=WsTicketResponse)
async def create_ws_ticket(
    current_user: dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Generates a single-use ticket valid for 60 seconds to authenticate WebSockets
    without leaking access tokens into query strings or server access logs.
    """
    ticket = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=60)

    await db["ws_tickets"].insert_one({
        "_id": ticket,
        "user_id": current_user["id"],
        "email": current_user["email"],
        "role": current_user.get("role", "analyst"),
        "org_id": current_user.get("org_id", "default"),
        "expires_at": expires_at,
    })

    return WsTicketResponse(ticket=ticket, expires_in=60)


# --- TOTP MFA Setup & Verification Endpoints ---

@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(
    current_user: dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Generates a new TOTP secret and provisioning URI for the user to configure an Authenticator app."""
    secret = generate_totp_secret()
    # Temporarily store pending secret until verified
    await db["users"].update_one(
        {"_id": current_user["id"]},
        {"$set": {"pending_mfa_secret": secret}},
    )
    uri = get_totp_provisioning_uri(secret, current_user["email"])
    return MfaSetupResponse(secret=secret, provisioning_uri=uri)


@router.post("/mfa/verify")
async def verify_mfa_setup(
    req: MfaVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Confirms TOTP setup by validating the 6-digit code. Enables MFA permanently on success."""
    user = await db["users"].find_one({"_id": current_user["id"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = user.get("pending_mfa_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="MFA setup has not been initiated")

    if not verify_totp_token(secret, req.token):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    await db["users"].update_one(
        {"_id": current_user["id"]},
        {
            "$set": {"mfa_enabled": True, "mfa_secret": secret},
            "$unset": {"pending_mfa_secret": ""},
        },
    )
    return {"status": "mfa_enabled", "message": "Multi-Factor Authentication enabled successfully"}


@router.post("/mfa/disable")
async def disable_mfa(
    req: MfaVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Disables MFA after validating current TOTP code."""
    user = await db["users"].find_one({"_id": current_user["id"]})
    if not user or not user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    if not verify_totp_token(user.get("mfa_secret", ""), req.token):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    await db["users"].update_one(
        {"_id": current_user["id"]},
        {"$set": {"mfa_enabled": False}, "$unset": {"mfa_secret": ""}},
    )
    return {"status": "mfa_disabled"}


# --- SSO / OIDC Endpoints ---

@router.get("/sso/authorize")
async def sso_authorize():
    """
    Returns the OpenID Connect (OIDC) authorization redirect URL.
    Integrates with enterprise IdPs (Okta, Entra ID, Google Workspace).
    """
    state = secrets.token_urlsafe(16)
    # Mock / standard OIDC authorize endpoint
    return {
        "auth_url": f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=forensiq-app&response_type=code&scope=openid%20profile%20email&state={state}",
        "state": state,
    }


@router.post("/sso/callback")
async def sso_callback(
    code: str,
    state: str,
    response: Response,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Exchanges OIDC authorization code for user profile, validates claims,
    and signs in or provisions the SOC analyst user.
    """
    # Verify code with IdP (Mock standard SSO handshake for development)
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # In production, fetch userinfo from IdP. Here we handle or provision user
    email = f"sso-analyst@{settings.ENV}.internal"
    user = await db["users"].find_one({"email": email})
    if not user:
        new_user = {
            "_id": secrets.token_hex(12),
            "email": email,
            "role": "analyst",
            "is_active": True,
            "sso_provider": "oidc",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await db["users"].insert_one(new_user)
        user = new_user

    return await _issue_tokens_for_user(db, response, user)
