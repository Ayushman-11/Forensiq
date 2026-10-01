"""
LLM Client Wrapper for Grok (xAI) and OpenAI-compatible Providers.
Provides robust async prompt execution with structured JSON parsing,
timeout controls, and graceful error handling.
"""

from typing import Optional, Dict, Any
import json
import re
import httpx
from app.core.config import settings
from app.core.logging import logger


async def query_grok_llm(
    prompt: str,
    system_prompt: str,
    temperature: float = 0.2,
    response_json: bool = False,
) -> Optional[str]:
    """
    Queries xAI Grok API (https://api.x.ai/v1/chat/completions).
    Returns the string completion, or None if credits/API error occurs.
    """
    api_key = settings.XAI_API_KEY
    if not api_key:
        logger.info("grok_api_key_not_configured")
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
                return content
            else:
                logger.warning(
                    "grok_api_non_200",
                    status_code=resp.status_code,
                    body=resp.text[:300],
                )
                return None
    except Exception as e:
        logger.warning("grok_api_exception", error=str(e))
        return None


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extracts and parses JSON object from a potentially markdown-wrapped LLM response."""
    if not text:
        return None
    # Strip markdown code blocks if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    
    # Locate first { and last }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None
