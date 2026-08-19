"""Tests for Settings fail-fast behavior around the insecure default SECRET_KEY.

Settings is a pydantic-settings BaseSettings subclass that normally reads
FORENSIQ_* env vars / .env at import time. To avoid leaking state between
tests (and to avoid mutating the global `settings` singleton used by the
rest of the app), these tests construct `Settings(...)` directly with
explicit kwargs and disable .env file loading via `_env_file=None`.
"""

import pytest

from app.core.config import Settings, DEFAULT_SECRET_KEY


def test_production_with_default_secret_key_raises():
    """Booting with ENV=production and the known-public default secret must
    fail fast rather than silently sign JWTs with a forgeable key."""
    with pytest.raises(ValueError):
        Settings(_env_file=None, ENV="production", SECRET_KEY=DEFAULT_SECRET_KEY)


def test_production_with_custom_secret_key_succeeds():
    """A production deployment that actually set a real secret must boot fine."""
    s = Settings(_env_file=None, ENV="production", SECRET_KEY="a-real-unique-production-secret-key-value")
    assert s.SECRET_KEY == "a-real-unique-production-secret-key-value"


def test_development_with_default_secret_key_is_allowed():
    """Local development must not be blocked by the fail-fast check."""
    s = Settings(_env_file=None, ENV="development", SECRET_KEY=DEFAULT_SECRET_KEY)
    assert s.SECRET_KEY == DEFAULT_SECRET_KEY


def test_env_comparison_is_case_insensitive():
    """ENV=Production / PRODUCTION should be treated the same as production."""
    with pytest.raises(ValueError):
        Settings(_env_file=None, ENV="Production", SECRET_KEY=DEFAULT_SECRET_KEY)
