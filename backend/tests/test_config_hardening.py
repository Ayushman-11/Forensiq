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


def test_prod_alias_with_short_secret_rejected():
    with pytest.raises(ValueError):
        Settings(**{**GOOD, "ENV": "prod", "SECRET_KEY": "short"})


def test_staging_with_insecure_values_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, ENV="staging", SECRET_KEY=DEFAULT_SECRET_KEY, SPLUNK_PASSWORD=DEFAULT_SPLUNK_PASSWORD, DEBUG=True)


@pytest.mark.parametrize("env", ["development", "dev", "test", "testing", "local", " LOCAL "])
def test_non_production_envs_unaffected(env):
    s = Settings(_env_file=None, ENV=env, SECRET_KEY=DEFAULT_SECRET_KEY, DEBUG=True)
    assert s.DEBUG is True


KEY_NAMES = ["VT_API_KEY", "ABUSEIPDB_API_KEY", "XAI_API_KEY"]


@pytest.fixture
def clean_key_env(monkeypatch):
    for name in KEY_NAMES:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"FORENSIQ_{name}", raising=False)
    return monkeypatch


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_prefixed_only(clean_key_env, name):
    clean_key_env.setenv(f"FORENSIQ_{name}", "prefixed-value")
    assert getattr(Settings(_env_file=None), name) == "prefixed-value"


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_unprefixed_only(clean_key_env, name):
    clean_key_env.setenv(name, "plain-value")
    assert getattr(Settings(_env_file=None), name) == "plain-value"


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_prefixed_wins_over_unprefixed(clean_key_env, name):
    clean_key_env.setenv(name, "plain-value")
    clean_key_env.setenv(f"FORENSIQ_{name}", "prefixed-value")
    assert getattr(Settings(_env_file=None), name) == "prefixed-value"


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_neither_is_empty(clean_key_env, name):
    assert getattr(Settings(_env_file=None), name) == ""


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_direct_kwarg_still_works(clean_key_env, name):
    assert getattr(Settings(_env_file=None, **{name: "kw"}), name) == "kw"


@pytest.mark.parametrize("name", KEY_NAMES)
def test_api_key_unprefixed_in_env_file(clean_key_env, tmp_path, name):
    env_file = tmp_path / ".env"
    env_file.write_text(f"{name}=from-file\n", encoding="utf-8")
    assert getattr(Settings(_env_file=str(env_file)), name) == "from-file"
