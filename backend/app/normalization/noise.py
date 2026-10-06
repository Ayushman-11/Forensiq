"""Data-driven noise suppression. Policy lives in config/noise.yaml."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.normalization.canonical import CanonicalEvent


class NoiseFilter:
    def __init__(self, benign_domains: list[str], rules: list[dict]) -> None:
        self.benign_domains = tuple(d.lower().rstrip(".") for d in benign_domains)
        self.rules = rules

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

    def _matches(self, rule: dict, ev: CanonicalEvent) -> bool:
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
        if "command_line_regex" in where and not re.search(where["command_line_regex"], ev.command_line or ""):
            return False
        return True

    def reason(self, event: CanonicalEvent) -> str | None:
        """Name of the first matching suppression rule, or None to keep the event."""
        for rule in self.rules:
            if self._matches(rule, event):
                return rule["name"]
        return None
