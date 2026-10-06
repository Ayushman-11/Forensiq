"""Data-driven noise suppression. Policy lives in config/noise.yaml."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.normalization.canonical import CanonicalEvent


_ALLOWED_WHERE_KEYS = {
    "subject_user_endswith", "domain_benign", "process_in", "parent_in",
    "command_line_regex", "process_path_startswith", "fields_regex",
}


def _compile(rule_name: str, key: str, pattern: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except (re.error, TypeError) as exc:
        raise ValueError(f"noise rule {rule_name!r}: invalid regex for {key}: {exc}") from exc


class NoiseFilter:
    def __init__(self, benign_domains: list[str], rules: list[dict]) -> None:
        self.benign_domains = tuple(d.lower().rstrip(".") for d in benign_domains)
        self.rules = rules
        self._cmd_re: dict[int, re.Pattern] = {}
        self._fields_re: dict[int, dict[str, re.Pattern]] = {}
        for i, rule in enumerate(rules):
            self._validate_rule(i, rule)

    def _validate_rule(self, index: int, rule: dict) -> None:
        if not isinstance(rule, dict) or not rule.get("name"):
            raise ValueError(f"noise rule #{index}: 'name' is required")
        name = rule["name"]
        where = rule.get("where")
        if not isinstance(where, dict) or not where:
            raise ValueError(f"noise rule {name!r}: 'where' must be a non-empty mapping")
        for key in where:
            if key not in _ALLOWED_WHERE_KEYS:
                raise ValueError(f"noise rule {name!r}: unknown where key {key!r}")
        if "command_line_regex" in where:
            self._cmd_re[index] = _compile(name, "command_line_regex", where["command_line_regex"])
        if "fields_regex" in where:
            fr = where["fields_regex"]
            if not isinstance(fr, dict) or not fr:
                raise ValueError(f"noise rule {name!r}: fields_regex must be a non-empty mapping")
            self._fields_re[index] = {f: _compile(name, f"fields_regex[{f}]", pat) for f, pat in fr.items()}

    @classmethod
    def from_dict(cls, cfg: dict) -> "NoiseFilter":
        return cls(cfg.get("benign_domains") or [], cfg.get("suppress") or [])

    @classmethod
    def from_yaml(cls, path: str | Path) -> "NoiseFilter":
        p = Path(path)
        if not p.is_absolute() and not p.exists():
            p = Path(__file__).resolve().parents[2] / p  # relative paths resolve from backend/ when cwd differs
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    def is_benign_domain(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        return any(d == b or d.endswith("." + b) for b in self.benign_domains)

    def _matches(self, rule: dict, ev: CanonicalEvent, index: int) -> bool:
        if rule.get("event_code") and str(rule["event_code"]) != ev.event_code:
            return False
        where = rule.get("where") or {}
        if "subject_user_endswith" in where and not (ev.subject_user or "").endswith(where["subject_user_endswith"]):
            return False
        if where.get("domain_benign") and not (ev.query_name and self.is_benign_domain(ev.query_name)):
            return False
        if "process_in" in where and (ev.process or "") not in [p.lower() for p in where["process_in"]]:
            return False
        if "process_path_startswith" in where:
            path = (ev.process_path or "").lower()
            if not path or not any(path.startswith(x.lower()) for x in where["process_path_startswith"]):
                return False
        if "parent_in" in where and (ev.parent or "") not in [p.lower() for p in where["parent_in"]]:
            return False
        if index in self._cmd_re and not self._cmd_re[index].search(ev.command_line or ""):
            return False
        for field, pattern in self._fields_re.get(index, {}).items():
            value = ev.fields.get(field)
            if value is None or not pattern.search(str(value)):
                return False
        return True

    def reason(self, event: CanonicalEvent) -> str | None:
        """Name of the first matching suppression rule, or None to keep the event."""
        for index, rule in enumerate(self.rules):
            if self._matches(rule, event, index):
                return rule["name"]
        return None
