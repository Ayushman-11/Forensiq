"""
Endpoints to inspect, test, and manage detection rules and MITRE ATT&CK coverage.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require_roles
from app.services.detection_rules import detection_engine, DetectionRule
from app.core.mitre_stix import ATTACK_VERSION, ATTACK_CATALOG, lookup_technique

router = APIRouter()
analyst_required = require_roles("admin", "senior_analyst", "analyst", "viewer")


class DetectionRuleOut(BaseModel):
    name: str
    description: str
    severity: str
    alert_type: str
    mitre_technique: str
    mitre_tactic: str
    owner: str
    tags: List[str]
    event_codes: List[str]
    last_fired: Optional[datetime] = None
    fire_count: int = 0


@router.get("", response_model=List[DetectionRuleOut])
@router.get("/", response_model=List[DetectionRuleOut])
async def list_detection_rules(_user: dict = Depends(analyst_required)):
    """Lists all active YAML and built-in detection rules with fire counts and last_fired timestamps."""
    rules = detection_engine.list_rules()
    return [
        DetectionRuleOut(
            name=r.name,
            description=r.description,
            severity=r.severity,
            alert_type=r.alert_type,
            mitre_technique=r.mitre_technique,
            mitre_tactic=r.mitre_tactic,
            owner=r.owner,
            tags=r.tags,
            event_codes=r.event_codes,
            last_fired=r.last_fired,
            fire_count=r.fire_count,
        )
        for r in rules
    ]


@router.get("/mitre-version")
async def get_mitre_version(_user: dict = Depends(analyst_required)):
    """Returns the pinned official ATT&CK STIX bundle version and technique statistics."""
    return {
        "attack_version": ATTACK_VERSION,
        "total_catalog_techniques": len(ATTACK_CATALOG),
        "source": "MITRE ATT&CK Enterprise Matrix (Official STIX v2.1)",
    }

