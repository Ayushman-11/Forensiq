"""
Per-tenant SLA targets and escalation policy.

Both live in the versioned `policies` collection (services/policy.py), so every change is audited
and reversible. Built-in defaults apply until a tenant saves its own. Targets are validated on
write and normalised on read, so the rest of the app can rely on `{severity: (ack_min, resolve_min)}`.
"""

from __future__ import annotations

from typing import Any

from app.services.policy import DEFAULT_SLA_MINUTES, get_active_policy

SEVERITIES = ("critical", "high", "medium", "low")
BREACH_KINDS = ("ack_breach", "resolve_breach")
MAX_MINUTES = 60 * 24 * 90  # 90 days: anything longer is a typo, not a target

# What happens when a clock is breached. Mirrors the pre-existing behaviour: tell everyone, and
# mark a critical alert Escalated when it blows its resolution target.
DEFAULT_ESCALATION: dict[str, dict[str, dict[str, Any]]] = {
    severity: {
        "ack_breach": {"notify": True, "reassign_to": None, "mark_escalated": False},
        "resolve_breach": {"notify": True, "reassign_to": None, "mark_escalated": severity == "critical"},
    }
    for severity in SEVERITIES
}


class PolicyValidationError(ValueError):
    pass


def normalise_sla(content: dict) -> dict[str, tuple[int, int]]:
    """Accepts {severity: [ack, resolve]} (as stored) and returns a complete tuple map."""
    targets: dict[str, tuple[int, int]] = {severity: (minutes[0], minutes[1]) for severity, minutes in DEFAULT_SLA_MINUTES.items()}
    for severity, pair in (content or {}).items():
        if severity not in SEVERITIES:
            raise PolicyValidationError(f"Unknown severity {severity!r}; use one of {list(SEVERITIES)}")
        try:
            ack, resolve = (int(pair[0]), int(pair[1]))
        except (TypeError, ValueError, IndexError, KeyError):
            raise PolicyValidationError(f"{severity}: expected [ack_minutes, resolve_minutes]")
        if not (1 <= ack <= MAX_MINUTES and 1 <= resolve <= MAX_MINUTES):
            raise PolicyValidationError(f"{severity}: minutes must be between 1 and {MAX_MINUTES}")
        if ack > resolve:
            raise PolicyValidationError(f"{severity}: acknowledge target cannot be later than the resolve target")
        targets[severity] = (ack, resolve)
    return targets


def normalise_escalation(content: dict) -> dict[str, dict[str, dict[str, Any]]]:
    """Fills gaps from DEFAULT_ESCALATION and rejects unknown severities, events or keys."""
    policy = {sev: {kind: dict(rule) for kind, rule in kinds.items()} for sev, kinds in DEFAULT_ESCALATION.items()}
    for severity, kinds in (content or {}).items():
        if severity not in SEVERITIES or not isinstance(kinds, dict):
            raise PolicyValidationError(f"Unknown severity {severity!r}; use one of {list(SEVERITIES)}")
        for kind, rule in kinds.items():
            if kind not in BREACH_KINDS or not isinstance(rule, dict):
                raise PolicyValidationError(f"{severity}: unknown event {kind!r}; use one of {list(BREACH_KINDS)}")
            unknown = set(rule) - {"notify", "reassign_to", "mark_escalated"}
            if unknown:
                raise PolicyValidationError(f"{severity}.{kind}: unknown keys {sorted(unknown)}")
            for flag in ("notify", "mark_escalated"):
                if flag in rule and not isinstance(rule[flag], bool):
                    raise PolicyValidationError(f"{severity}.{kind}.{flag} must be true or false")
            if rule.get("reassign_to") is not None and not isinstance(rule["reassign_to"], str):
                raise PolicyValidationError(f"{severity}.{kind}.reassign_to must be a user id or null")
            policy[severity][kind].update(rule)
    return policy


async def get_sla_targets(db, org_id: str) -> dict[str, tuple[int, int]]:
    """The tenant's SLA targets. A corrupt stored policy falls back to the defaults, never to an error."""
    try:
        return normalise_sla(await get_active_policy(db, org_id, "sla_targets"))
    except PolicyValidationError:
        return {severity: (minutes[0], minutes[1]) for severity, minutes in DEFAULT_SLA_MINUTES.items()}


async def get_escalation_policy(db, org_id: str) -> dict[str, dict[str, dict[str, Any]]]:
    try:
        return normalise_escalation(await get_active_policy(db, org_id, "escalation"))
    except PolicyValidationError:
        return normalise_escalation({})
