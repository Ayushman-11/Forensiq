"""Tests for password hashing and JWT helpers."""

import pytest
from datetime import datetime, timezone

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    TokenError,
)


def test_hash_password_roundtrip():
    hashed = hash_password("correct-horse-battery-staple")
    assert hashed != "correct-horse-battery-staple"
    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", hashed) is False


def test_create_and_decode_access_token():
    token = create_access_token(user_id="user123", email="a@b.com", role="admin")
    payload = decode_token(token)
    assert payload["sub"] == "user123"
    assert payload["email"] == "a@b.com"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_create_and_decode_refresh_token():
    token, jti, expires_at = create_refresh_token(user_id="user123")
    payload = decode_token(token)
    assert payload["sub"] == "user123"
    assert payload["type"] == "refresh"
    assert payload["jti"] == jti
    assert isinstance(expires_at, datetime)
    assert expires_at > datetime.now(timezone.utc)


def test_decode_token_rejects_garbage():
    with pytest.raises(TokenError):
        decode_token("not-a-real-token")
