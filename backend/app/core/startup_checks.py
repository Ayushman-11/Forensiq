"""Startup configuration checks (pure functions, no I/O, never touch secret values)."""

from __future__ import annotations

from typing import Any

_THREAT_INTEL_KEYS = ("VT_API_KEY", "ABUSEIPDB_API_KEY")
_LLM_KEYS = ("XAI_API_KEY",)


def missing_integrations(settings: Any) -> dict[str, list[str]]:
    """Return the empty API-key setting names per integration; groups with nothing missing are omitted."""
    def empty(names: tuple[str, ...]) -> list[str]:
        return [n for n in names if not str(getattr(settings, n, "") or "").strip()]

    result = {"threat_intel": empty(_THREAT_INTEL_KEYS), "llm": empty(_LLM_KEYS)}
    return {group: names for group, names in result.items() if names}
