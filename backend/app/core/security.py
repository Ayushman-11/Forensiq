"""
Password hashing, JWT access/refresh token helpers, TOTP (RFC 6238), and ticket handling.
Supports graceful dual-key rotation: verifies against active SECRET_KEY first,
then falls back to PREVIOUS_SECRET_KEY for one token TTL window.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional

from jose import jwt, JWTError
import bcrypt

from app.core.config import settings


class TokenError(Exception):
    """Raised when a JWT cannot be decoded or verified."""


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def create_access_token(user_id: str, email: str, role: str, org_id: str = "default") -> str:
    """Creates a short-lived JWT access token carrying user identity, org, and role using active SECRET_KEY."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "org_id": org_id,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: str) -> Tuple[str, str, datetime]:
    """
    Creates a long-lived JWT refresh token using active SECRET_KEY. Returns (token, jti, expires_at)
    so the caller can persist a matching session row for revocation/rotation.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": expire,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti, expire


def create_mfa_token(user_id: str, email: str, role: str) -> str:
    """Creates a short-lived (5 min) intermediate token required to complete MFA challenge."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=5)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "type": "mfa_pending",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decodes and verifies a JWT.
    Supports key rotation: tries settings.SECRET_KEY first.
    If validation fails and settings.PREVIOUS_SECRET_KEY is configured,
    tries decoding with PREVIOUS_SECRET_KEY before rejecting.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as primary_err:
        if settings.PREVIOUS_SECRET_KEY:
            try:
                return jwt.decode(token, settings.PREVIOUS_SECRET_KEY, algorithms=[settings.ALGORITHM])
            except JWTError:
                pass
        raise TokenError(str(primary_err)) from primary_err


# --- RFC 6238 TOTP (Time-Based One-Time Password) Implementation ---

def generate_totp_secret() -> str:
    """Generates a base32-encoded 160-bit secret key for RFC 6238 TOTP."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode('utf-8').rstrip('=')


def get_totp_token(secret: str, interval: int = 30, for_time: Optional[int] = None) -> str:
    """Calculates the 6-digit TOTP token for the given base32 secret and timestamp."""
    if for_time is None:
        for_time = int(time.time())
    
    pad_len = (8 - (len(secret) % 8)) % 8
    padded_secret = secret.upper() + ("=" * pad_len)
    key = base64.b32decode(padded_secret, casefold=True)

    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp_token(secret: str, token: str, window: int = 1, interval: int = 30) -> bool:
    """
    Verifies a 6-digit TOTP token against a base32 secret within ±window steps
    to allow for reasonable clock skew.
    """
    if not token or len(token.strip()) != 6 or not token.strip().isdigit():
        return False
    
    now = int(time.time())
    token_str = token.strip()
    for w in range(-window, window + 1):
        if hmac.compare_digest(get_totp_token(secret, interval, now + (w * interval)), token_str):
            return True
    return False


def get_totp_provisioning_uri(secret: str, account_name: str, issuer: str = "Forensiq SOC") -> str:
    """Formats an otpauth:// TOTP URI suitable for standard authenticator QR codes."""
    import urllib.parse
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    issuer_param = urllib.parse.quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_param}&algorithm=SHA1&digits=6&period=30"
