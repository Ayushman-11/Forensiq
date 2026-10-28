"""
Unified Investigation Streaming Service for WebSocket & SSE.
Handles LangGraph multi-agent pipeline streaming, pub/sub broadcasting to connected
WebSockets, and real-time state synchronization.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from fastapi import WebSocket
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.agents.graph import investigation_graph
from app.services.correlation import correlate_alert
from app.core.timeutil import iso_utc
from app.core.logging import logger
from app.core.errors import new_request_id


STEP_DEFINITIONS = {
    "extract_context": {
        "step": 1,
        "name": "Context Extraction",
        "description": "Analyzing raw telemetry, host & user context",
    },
    "enrich_iocs": {
        "step": 2,
        "name": "Threat Intel & Cache Lookup",
        "description": "Enriching IOCs via VirusTotal & AbuseIPDB with cache lookup",
    },
    "correlate_events": {
        "step": 3,
        "name": "Historical Event Correlation",
        "description": "Searching across tenant alert history for related entities",
    },
    "map_mitre": {
        "step": 4,
        "name": "MITRE ATT&CK Mapping",
        "description": "Mapping behavioral heuristics to MITRE tactics and techniques",
    },
    "build_timeline": {
        "step": 5,
        "name": "Chronological Timeline Assembly",
        "description": "Sorting multi-source events into attack lifecycle phases",
    },
    "assess_risk": {
        "step": 6,
        "name": "Risk Assessment",
        "description": "Evaluating threat severity, blast radius, and confidence score",
    },
    "generate_recommendations": {
        "step": 7,
        "name": "Incident Response Recommendations",
        "description": "Synthesizing mitigation playbooks and actionable next steps",
    },
}


def json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return iso_utc(obj)
    if hasattr(obj, "__str__") and type(obj).__name__ == "ObjectId":
        return str(obj)
    return str(obj)


def serialize_data(data: Any) -> Any:
    """Recursively converts datetimes, ObjectIds, and sets to serializable formats."""
    if isinstance(data, dict):
        return {k: serialize_data(v) for k, v in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [serialize_data(x) for x in data]
    if isinstance(data, datetime):
        return iso_utc(data)
    if hasattr(data, "__str__") and type(data).__name__ == "ObjectId":
        return str(data)
    return data


def make_step_summary(node_name: str, node_output: dict) -> str:
    """Generates an analyst-facing summary for a completed pipeline node."""
    if node_name == "extract_context":
        iocs = node_output.get("extracted_iocs", [])
        if iocs:
            return f"Extracted {len(iocs)} indicators of compromise: {', '.join(str(i) for i in iocs[:3])}"
        return "No distinct IOCs extracted from raw telemetry."

    elif node_name == "enrich_iocs":
        res = node_output.get("enrichment_results", [])
        mal = sum(1 for r in res if isinstance(r, dict) and r.get("reputation") == "malicious")
        cached = sum(1 for r in res if isinstance(r, dict) and r.get("cached"))
        return f"Enriched {len(res)} threat feeds ({mal} malicious, {cached} cached)."

    elif node_name == "correlate_events":
        corrs = node_output.get("correlations", [])
        return f"Correlated {len(corrs)} related alert(s) across historical telemetry."

    elif node_name == "map_mitre":
        mappings = node_output.get("mitre_mappings", [])
        if mappings:
            techniques = [m.get("technique", "") for m in mappings if isinstance(m, dict) and m.get("technique")]
            return f"Mapped {len(mappings)} MITRE technique(s): {', '.join(techniques[:2])}"
        return "No MITRE techniques mapped."

    elif node_name == "build_timeline":
        tl = node_output.get("timeline", [])
        phases = {e.get("phase") for e in tl if isinstance(e, dict) and e.get("phase")}
        return f"Assembled {len(tl)} chronological events across {len(phases)} attack phase(s)."

    elif node_name == "assess_risk":
        risk = node_output.get("risk_assessment", {})
        score = risk.get("risk_score", 0) if isinstance(risk, dict) else 0
        priority = (risk.get("priority", "medium") if isinstance(risk, dict) else "medium").upper()
        return f"Risk Score: {score}/100 ({priority} Priority)."

    elif node_name == "generate_recommendations":
        return "Actionable incident response checklist generated."

    return "Agent task completed."


async def finalize_and_save_investigation(
    db: AsyncIOMotorDatabase,
    alert_id: str,
    job_id: str,
    alert: dict,
    final_state: dict,
) -> dict:
    """Consolidates graph state results and persists them to alerts and investigation_jobs."""
    enrichments = final_state.get("enrichment_results", [])
    context = final_state.get("context", {})
    extracted_iocs = final_state.get("extracted_iocs", [])
    investigation_log = final_state.get("investigation_log", [])
    risk_assessment = final_state.get("risk_assessment", {})
    mitre_mappings = final_state.get("mitre_mappings", [])
    timeline = final_state.get("timeline", [])
    recommendation = final_state.get("recommendation")
    correlations = final_state.get("correlations")
    if correlations is None:
        try:
            correlations = await correlate_alert(db, alert)
        except Exception:
            correlations = []

    evidence = {
        "ioc_count": len(extracted_iocs),
        "enrichment_count": len(enrichments),
        "correlated_alert_count": len(correlations) if isinstance(correlations, list) else 0,
        "mitre_count": len(mitre_mappings),
    }

    # Confidence is whatever the risk engine reported; no extra boosts on top.
    ai_confidence = risk_assessment.get("confidence_score", 0)
    engines = {
        "risk": risk_assessment.get("engine", "unknown"),
        "recommendation": final_state.get("recommendation_engine") or "unknown",
    }
    unavailable_feeds = sorted({
        e.get("source") for e in enrichments
        if isinstance(e, dict) and e.get("status", "ok") != "ok" and e.get("source")
    })

    alert_update = {
        "status": "Investigated",
        "ai_confidence": ai_confidence,
        "context": context,
        "enrichments": enrichments,
        "extracted_iocs": extracted_iocs,
        "risk_assessment": risk_assessment,
        "risk_score": risk_assessment.get("risk_score", 0),
        "priority": risk_assessment.get("priority", "medium"),
        "mitre_mappings": mitre_mappings,
        "timeline": timeline,
        "recommendation": recommendation,
        "correlations": correlations,
        "evidence": evidence,
        "engines": engines,
        "unavailable_feeds": unavailable_feeds,
    }

    await db["alerts"].update_one(
        {"_id": alert_id},
        {"$set": alert_update},
    )

    await db["investigation_jobs"].update_one(
        {"_id": job_id},
        {"$set": {
            "status": "complete",
            "completed_at": datetime.now(timezone.utc),
            "logs": investigation_log,
            "context": context,
            "enrichments": enrichments,
            "risk_assessment": risk_assessment,
            "mitre_mappings": mitre_mappings,
            "timeline": timeline,
            "recommendation": recommendation,
            "correlations": correlations,
            "evidence": evidence,
            "engines": engines,
        }}
    )
    logger.info("investigation_completed_and_saved", job_id=job_id, alert_id=alert_id)
    return {**alert, **alert_update}


def reconstruct_steps_from_alert(alert: dict) -> List[dict]:
    """Reconstructs node_complete step payloads for an alert that was previously investigated."""
    steps_data = []

    # 1. extract_context
    steps_data.append({
        "node": "extract_context",
        "data": {
            "context": alert.get("context", {}),
            "extracted_iocs": alert.get("extracted_iocs", []),
        },
    })

    # 2. enrich_iocs
    steps_data.append({
        "node": "enrich_iocs",
        "data": {
            "enrichment_results": alert.get("enrichments", []),
        },
    })

    # 3. correlate_events
    steps_data.append({
        "node": "correlate_events",
        "data": {
            "correlations": alert.get("correlations", []),
        },
    })

    # 4. map_mitre
    steps_data.append({
        "node": "map_mitre",
        "data": {
            "mitre_mappings": alert.get("mitre_mappings", []),
        },
    })

    # 5. build_timeline
    steps_data.append({
        "node": "build_timeline",
        "data": {
            "timeline": alert.get("timeline", []),
        },
    })

    # 6. assess_risk
    steps_data.append({
        "node": "assess_risk",
        "data": {
            "risk_assessment": alert.get("risk_assessment", {}),
        },
    })

    # 7. generate_recommendations
    steps_data.append({
        "node": "generate_recommendations",
        "data": {
            "recommendation": alert.get("recommendation"),
        },
    })

    events = []
    for s in steps_data:
        node_name = s["node"]
        meta = STEP_DEFINITIONS.get(node_name, {"step": 0, "name": node_name, "description": ""})
        summary = make_step_summary(node_name, s["data"])
        events.append({
            "node": node_name,
            "step": meta["step"],
            "name": meta["name"],
            "description": meta["description"],
            "status": "completed",
            "summary": summary,
            "data": serialize_data(s["data"]),
        })

    return events


class InvestigationStreamManager:
    """
    Manages active WebSocket subscribers and orchestrates pipeline streaming.
    Provides pub/sub broadcasting per alert_id, ensuring seamless real-time
    updates across all connected clients.
    """

    def __init__(self):
        self._subscribers: Dict[str, Set[WebSocket]] = {}
        self._event_history: Dict[str, List[dict]] = {}
        self._active_runs: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    def register(self, alert_id: str, ws: WebSocket) -> None:
        """Subscribes a WebSocket client to alert investigation events."""
        if alert_id not in self._subscribers:
            self._subscribers[alert_id] = set()
        self._subscribers[alert_id].add(ws)
        logger.info("ws_client_registered", alert_id=alert_id, total_subscribers=len(self._subscribers[alert_id]))

    def unregister(self, alert_id: str, ws: WebSocket) -> None:
        """Removes a WebSocket client subscription."""
        if alert_id in self._subscribers:
            self._subscribers[alert_id].discard(ws)
            if not self._subscribers[alert_id]:
                del self._subscribers[alert_id]
        logger.info("ws_client_unregistered", alert_id=alert_id)

    async def broadcast(
        self,
        alert_id: str,
        event_type: str,
        data: dict,
        db: Optional[AsyncIOMotorDatabase] = None,
        job_id: Optional[str] = None,
    ) -> None:
        """
        Broadcasts an investigation event to all registered WebSocket clients for this alert
        and persists it to MongoDB investigation_events for multi-worker support.
        """
        message = {
            "event": event_type,
            "data": serialize_data(data),
        }

        # Cache event in history for late arrivals
        if alert_id not in self._event_history:
            self._event_history[alert_id] = []
        if event_type in ("init", "node_complete"):
            self._event_history[alert_id].append(message)
        elif event_type in ("complete", "error"):
            # Clear or retain final state
            self._event_history[alert_id].append(message)

        # Persist event for multi-process / multi-worker pub-sub
        if db is not None:
            try:
                await db["investigation_events"].insert_one({
                    "_id": str(uuid.uuid4()),
                    "alert_id": alert_id,
                    "job_id": job_id,
                    "event": event_type,
                    "data": serialize_data(data),
                    "created_at": datetime.now(timezone.utc),
                })
            except Exception as exc:
                logger.debug("event_persistence_failed", alert_id=alert_id, error=str(exc))

        subscribers = self._subscribers.get(alert_id, set()).copy()
        if not subscribers:
            return

        dead_sockets: List[WebSocket] = []
        payload_text = json.dumps(message, default=json_serial)

        for ws in subscribers:
            try:
                await ws.send_text(payload_text)
            except Exception as e:
                logger.debug("ws_send_failed_removing", alert_id=alert_id, error=str(e))
                dead_sockets.append(ws)

        for ws in dead_sockets:
            self.unregister(alert_id, ws)

    def get_history(self, alert_id: str) -> List[dict]:
        """Returns in-flight event history for an alert from local memory."""
        return list(self._event_history.get(alert_id, []))

    async def get_persisted_history(self, alert_id: str, db: AsyncIOMotorDatabase) -> List[dict]:
        """Returns in-flight or past event history from MongoDB for multi-worker support."""
        events = []
        try:
            cursor = db["investigation_events"].find({"alert_id": alert_id}).sort("created_at", 1)
            async for doc in cursor:
                events.append({
                    "event": doc.get("event"),
                    "data": doc.get("data"),
                })
        except Exception as exc:
            logger.debug("failed_to_fetch_persisted_events", alert_id=alert_id, error=str(exc))
        
        # If DB had events, return them; otherwise fallback to local memory
        return events if events else self.get_history(alert_id)

    def clear_history(self, alert_id: str) -> None:
        """Clears in-flight history for an alert."""
        self._event_history.pop(alert_id, None)

    async def run_pipeline_stream(
        self,
        alert_id: str,
        alert: dict,
        db: AsyncIOMotorDatabase,
        job_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> AsyncGenerator[dict, None]:
        """
        Executes the LangGraph investigation pipeline while:
        1. Yielding events as dicts (for SSE consumption)
        2. Broadcasting events to all registered WebSockets simultaneously
        3. Persisting finalized results to MongoDB
        """
        if not job_id:
            job_id = str(uuid.uuid4())

        self.clear_history(alert_id)

        # Record job in database. Upsert: POST /investigate creates the row before the run starts.
        now = datetime.now(timezone.utc)
        await db["investigation_jobs"].update_one(
            {"_id": job_id},
            {
                "$set": {"status": "running", "started_at": now},
                "$setOnInsert": {
                    "alert_id": alert_id,
                    "created_at": now,
                    "org_id": org_id or alert.get("org_id", "default"),
                },
            },
            upsert=True,
        )

        # Update alert status
        await db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {"status": "Investigating"}},
        )

        init_payload = {
            "job_id": job_id,
            "alert_id": alert_id,
            "total_steps": len(STEP_DEFINITIONS),
            "status": "running",
            "message": "Investigation pipeline initialized",
        }
        await self.broadcast(alert_id, "init", init_payload, db=db, job_id=job_id)
        yield {"event": "init", "data": init_payload}

        initial_state = {
            "alert_data": alert,
            "context": {},
            "extracted_iocs": alert.get("extracted_iocs", []),
            "enrichment_results": [],
            "investigation_log": [f"Investigation started for alert {alert_id}"],
            "ai_analysis": None,
            "risk_assessment": {},
            "mitre_mappings": [],
            "correlations": [],
            "timeline": [],
            "recommendation": None,
            "recommendation_engine": None,
        }

        accumulated_state = dict(initial_state)

        try:
            async for chunk in investigation_graph.astream(initial_state):
                for node_name, node_output in chunk.items():
                    accumulated_state.update(node_output)
                    meta = STEP_DEFINITIONS.get(node_name, {
                        "step": 0,
                        "name": node_name,
                        "description": "",
                    })

                    summary = make_step_summary(node_name, node_output)
                    node_event = {
                        "job_id": job_id,
                        "node": node_name,
                        "step": meta["step"],
                        "name": meta["name"],
                        "description": meta["description"],
                        "status": "completed",
                        "summary": summary,
                        "data": {k: v for k, v in node_output.items() if k != "alert_data"},
                    }

                    await self.broadcast(alert_id, "node_complete", node_event, db=db, job_id=job_id)
                    yield {"event": "node_complete", "data": node_event}

            # Finalize and persist in MongoDB
            final_alert = await finalize_and_save_investigation(
                db=db,
                alert_id=alert_id,
                job_id=job_id,
                alert=alert,
                final_state=accumulated_state,
            )

            serialized_alert = serialize_data(final_alert)
            complete_event = {
                "job_id": job_id,
                "alert_id": alert_id,
                "status": "complete",
                "message": "Investigation successfully finished",
                "alert": serialized_alert,
            }

            await self.broadcast(alert_id, "complete", complete_event, db=db, job_id=job_id)
            yield {"event": "complete", "data": complete_event}

        except Exception as e:
            ref = new_request_id()
            logger.error("investigation_stream_failed", request_id=ref, alert_id=alert_id, error=str(e))
            await db["investigation_jobs"].update_one(
                {"_id": job_id},
                {"$set": {
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "error": "investigation_failed",
                    "error_ref": ref,
                }}
            )
            await db["alerts"].update_one(
                {"_id": alert_id},
                {"$set": {"status": "Investigation Failed"}},
            )
            error_payload = {
                "job_id": job_id,
                "alert_id": alert_id,
                "error": f"Investigation failed (ref {ref})",
            }
            await self.broadcast(alert_id, "error", error_payload, db=db, job_id=job_id)
            yield {"event": "error", "data": error_payload}


# Global singleton instance
investigation_stream_manager = InvestigationStreamManager()
