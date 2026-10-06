import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "splunk_rows.json"
ROOT = Path(__file__).resolve().parents[2]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+")
OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?:10\.%s\.%s\.%s|172\.(?:1[6-9]|2\d|3[01])\.%s\.%s|192\.168\.%s\.%s)(?!\d|\.\d)"
    % ((OCT,) * 7)
)
SID_PSEUDONYM = "S-1-5-21-1000000000-2000000000-3000000000"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "export_fixture_rows", Path(__file__).parents[1] / "scripts" / "export_fixture_rows.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fixture_contains_no_personal_identifiers():
    text = FIXTURE.read_text(encoding="utf-8")
    assert set(EMAIL_RE.findall(text)) <= {"analyst@example.test"}
    assert set(SID_RE.findall(text)) <= {SID_PSEUDONYM}
    assert set(PRIVATE_IP_RE.findall(text)) <= {"10.0.0.5"}
    assert not re.search("ay" + "ush", text, re.I)
    assert not re.search("kum" + "bhar", text, re.I)


def test_pseudonymize_is_stable_and_case_preserving():
    mod = _load_script()
    name = "ay" + "ush"
    src = (
        f"{name.upper()} {name.capitalize()} {name} Jane.Doe@corp.example "
        "S-1-5-21-111-222-333-1001 S-1-5-18 10.1.2.3 192.168.5.6 172.20.1.1 "
        "172.32.1.1 10.0.22621.3085 10.0.14393.206"
    )
    out = mod.pseudonymize(src)
    assert "LABUSER" in out and "Labuser" in out and "labuser" in out
    assert "analyst@example.test" in out and "corp.example" not in out
    assert f"{SID_PSEUDONYM}-1001" in out
    assert "S-1-5-18" in out  # well-known short SIDs are untouched
    assert out.count("10.0.0.5") == 3
    assert "172.32.1.1" in out  # outside RFC1918 172.16-31
    assert "10.0.22621.3085" in out  # OS build numbers are not IP addresses
    assert "10.0.14393.206" in out
    assert mod.pseudonymize(out) == out


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_database_dumps_are_not_tracked():
    tracked = subprocess.run(["git", "ls-files", "backend/mongo_dump_json"], cwd=ROOT, capture_output=True, text=True).stdout
    assert tracked.strip() == ""
