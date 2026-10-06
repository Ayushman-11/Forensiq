import re
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "splunk_rows.json"
ROOT = Path(__file__).resolve().parents[2]


def test_fixture_contains_no_personal_identifiers():
    text = FIXTURE.read_text(encoding="utf-8")
    assert not re.search(r"ayush", text, re.I)
    assert "@gmail.com" not in text
    assert not re.search(r"S-1-5-21-4283746528", text)
    assert "10.143.71.72" not in text


def test_pseudonymize_is_stable_and_case_preserving():
    import importlib.util
    spec = importlib.util.spec_from_file_location("export_fixture_rows", Path(__file__).parents[1] / "scripts" / "export_fixture_rows.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = mod.pseudonymize("AYUSH Ayush ayush ayushkumbhar1111@gmail.com S-1-5-21-4283746528-2832981674-120407787-1001 10.143.71.72 10.0.22621.3085")
    assert "LABUSER" in out and "Labuser" in out and "labuser" in out
    assert "analyst@example.test" in out
    assert "S-1-5-21-1000000000-2000000000-3000000000-1001" in out
    assert "10.0.0.5" in out
    assert "10.0.22621.3085" in out  # OS build numbers are not IP addresses


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_database_dumps_are_not_tracked():
    tracked = subprocess.run(["git", "ls-files", "backend/mongo_dump_json"], cwd=ROOT, capture_output=True, text=True).stdout
    assert tracked.strip() == ""
