import pytest

from app.services.spl_guard import ALLOWED_COMMANDS, SPLRejected, validate_search, validate_time_range

KW = dict(allowed_indexes=["windows"], default_index="windows")


def ok(q):
    return validate_search(q, **KW)


def test_adds_search_prefix_and_default_index():
    assert ok("EventCode=4625") == "search index=windows EventCode=4625"
    assert ok("search EventCode=1 | head 50") == "search index=windows EventCode=1 | head 50"


def test_explicit_allowed_index_is_kept_and_not_duplicated():
    out = ok('search index="windows" EventCode=3 | stats count by host | sort -count')
    assert out.count("index=") == 1 and out.startswith("search ")
    assert ok("index=WINDOWS | head 5").startswith("search index=WINDOWS")


@pytest.mark.parametrize("cmd", [
    "delete", "outputlookup x", "outputcsv x", "rest /services/server/info", "collect index=x", "sendemail to=a@b.c",
    "script foo", "map search=\"x\"", "tstats count", "makeresults", "inputlookup x", "loadjob 1", "dbxquery q", "run foo",
])
def test_disallowed_commands_are_rejected(cmd):
    with pytest.raises(SPLRejected):
        ok(f"search EventCode=1 | {cmd}")


def test_every_allowed_command_is_accepted():
    for cmd in sorted(ALLOWED_COMMANDS - {"search"}):
        ok(f"EventCode=1 | {cmd} host")


@pytest.mark.parametrize("q", [
    "| rest /services/x", "|makeresults", "EventCode=1 [ search index=other | fields host ]", "EventCode=1 `macro`",
    "index=other EventCode=1", "index=* EventCode=1", "index!=windows", "index IN (windows, other)",
    "index=windows OR index=secret", "index=windows | search index=other",
    "EventCode=1 earliest=-1y", "index=windows latest=+1d", "EventCode=1 _index_earliest=-5y",
    "", "   ", 'EventCode="unterminated', "x" * 4001, " | ".join(["head 1"] * 12),
    "EventCode=1 | head 5 | | head 2",
])
def test_bad_queries_are_rejected(q):
    with pytest.raises(SPLRejected):
        ok(q)


def test_quoted_pipes_and_brackets_are_data_not_syntax():
    out = ok('CommandLine="a | b [c]" | head 5')
    assert 'CommandLine="a | b [c]"' in out and out.endswith("| head 5")


def test_time_range_accepts_relative_within_limit():
    validate_time_range("-15m", "now", 30)
    validate_time_range("-24h", "now", 30)
    validate_time_range("-30d", "-5m", 30)


@pytest.mark.parametrize("earliest,latest", [
    ("-31d", "now"), ("-5w", "now"), ("2026-01-01T00:00:00", "now"), ("0", "now"), ("-1h", "+1h"),
    ("-5m", "-10m"), ("-0m", "now"), ("", "now"), ("-1h", "2026-01-01"), ("-1x", "now"),
])
def test_time_range_rejections(earliest, latest):
    with pytest.raises(SPLRejected):
        validate_time_range(earliest, latest, 30)


def test_boolean_operators_and_parentheses_are_wrapped_under_default_index():
    assert ok("foo OR index=windows") == "search index=windows (foo OR index=windows)"
    assert ok("NOT index=windows foo") == "search index=windows (NOT index=windows foo)"
    assert ok("(EventCode=1 OR EventCode=3) host=x | head 5") == "search index=windows ((EventCode=1 OR EventCode=3) host=x) | head 5"
    assert ok("not index=windows") == "search index=windows (not index=windows)"


def test_quoted_or_does_not_wrap():
    assert ok('CommandLine="a OR b"') == 'search index=windows CommandLine="a OR b"'


@pytest.mark.parametrize("q", [
    "foo) OR (bar", "(foo", "foo)", "x | where (a=1", "EventCode=1\x00", "EventCode=1\x1b[0m",
])
def test_unbalanced_parens_and_control_chars_rejected(q):
    with pytest.raises(SPLRejected):
        ok(q)


def test_tab_newline_cr_still_accepted():
    ok("EventCode=1\t| head 5\n")
    ok("EventCode=1\r\n| head 5")


@pytest.mark.parametrize("q", [
    "EventCode=1", "search EventCode=1 | head 5", "index=windows foo", 'index="windows" a=b | stats count',
    "foo OR bar", "foo OR index=windows", "NOT index=windows foo", "not foo", "(a=1 OR b=2) c=3",
    "((a=1))", 'x="a OR b"', "a=1 AND (b=2 OR NOT c=3) | sort -count", "index=WINDOWS OR foo",
    "EventCode=1 | where (a=1 OR b=2)", "foo (bar OR index=windows) | head 1",
])
def test_every_accepted_query_is_scoped_to_allowed_index(q):
    out = ok(q)
    assert out.replace('"', "").lower().startswith("search index=windows")
    first = out.split(" | ")[0]
    values = {v.lower() for _, v in __import__("re").findall(r'\bindex\s*(!=|=)\s*"?([^\s")|,]+)', first)}
    assert values == {"windows"}
