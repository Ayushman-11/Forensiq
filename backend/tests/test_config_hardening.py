import pytest

from app.core.config import DEFAULT_SECRET_KEY, DEFAULT_SPLUNK_PASSWORD, Settings

GOOD = dict(_env_file=None, ENV="production", SECRET_KEY="x" * 40, SPLUNK_PASSWORD="a-real-splunk-password", DEBUG=False)


def test_safe_defaults():
    s = Settings(_env_file=None)
    assert s.DEBUG is False
    assert s.ACCESS_TOKEN_EXPIRE_MINUTES == 30
    assert s.SPLUNK_ALLOWED_INDEXES == ["windows"]
    assert s.SEARCH_MAX_RANGE_DAYS == 30
    assert s.LOGIN_MAX_FAILURES == 5 and s.LOGIN_LOCKOUT_MINUTES == 15


def test_valid_production_settings_boot():
    assert Settings(**GOOD).ENV == "production"


@pytest.mark.parametrize("override", [
    {"SECRET_KEY": "short-secret"},
    {"SECRET_KEY": DEFAULT_SECRET_KEY},
    {"SPLUNK_PASSWORD": DEFAULT_SPLUNK_PASSWORD},
    {"DEBUG": True},
    {"SPLUNK_PASSWORD": ""},
    {"ENV": " Production ", "SECRET_KEY": DEFAULT_SECRET_KEY},
])
def test_production_rejects_insecure_values(override):
    with pytest.raises(ValueError):
        Settings(**{**GOOD, **override})


def test_development_is_not_blocked():
    s = Settings(_env_file=None, ENV="development", SECRET_KEY=DEFAULT_SECRET_KEY, DEBUG=True)
    assert s.DEBUG is True
