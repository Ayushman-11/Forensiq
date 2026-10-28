"""
LLM Client Wrapper for Grok (xAI) and OpenAI-compatible Providers.
Provides robust async prompt execution with structured JSON parsing,
timeout controls, circuit breaker protection, and token cost tracking.
"""

from typing import Optional, Dict, Any, Tuple
import json
import re
import httpx
from app.core.config import settings
from app.core.logging import logger
from app.services.llm_governance import llm_governance

# Thread-local / module-level store of latest LLM query metadata
_latest_query_metadata: Dict[str, Any] = {}


def get_latest_query_metadata() -> Dict[str, Any]:
    """Returns the metadata (model, tokens, cost) from the most recent LLM invocation."""
    return dict(_latest_query_metadata)


async def query_grok_llm(
    prompt: str,
    system_prompt: str,
    temperature: float = 0.2,
    response_json: bool = False,
    db: Any = None,
    org_id: str = "default",
) -> Optional[str]:
    """
    Queries xAI Grok API (https://api.x.ai/v1/chat/completions).
    Enforces circuit breaker checks and tenant daily spending limits.
    Returns the string completion, or None if credits/API error/budget cap occurs.
    """
    global _latest_query_metadata
    api_key = settings.XAI_API_KEY
    if not api_key:
        logger.info("grok_api_key_not_configured")
        return None

    # 1. Check Circuit Breaker and Tenant Daily Budget
    allowed, reason = await llm_governance.can_query_llm(db, org_id)
    if not allowed:
        logger.warning("grok_query_governance_rejection", reason=reason, org_id=org_id)
        return None

    url = f"{settings.XAI_BASE_URL.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload: Dict[str, Any] = {
        "model": settings.XAI_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
    }

    if response_json:
        payload["response_format"] = {"type": "json_object"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]

                # Extract token usage
                usage = data.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens", max(1, len(prompt) // 4))
                completion_tokens = usage.get("completion_tokens", max(1, len(content) // 4))

                # Record cost and reset circuit breaker
                usage_record = await llm_governance.record_usage(db, org_id, prompt_tokens, completion_tokens)
                await llm_governance.circuit_breaker.record_success()

                _latest_query_metadata = {
                    "model": settings.XAI_MODEL,
                    "prompt_version": settings.LLM_PROMPT_VERSION,
                    **usage_record,
                }
                return content
            else:
                await llm_governance.circuit_breaker.record_failure()
                logger.warning(
                    "grok_api_non_200",
                    status_code=resp.status_code,
                    body=resp.text[:300],
                )
                return None
    except Exception as e:
        await llm_governance.circuit_breaker.record_failure()
        logger.warning("grok_api_exception", error=str(e))
        return None


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extracts and parses JSON object from a potentially markdown-wrapped LLM response."""
    if not text:
        return None
    cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None
