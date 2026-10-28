"""
LLM Governance, Rate Limiting, Cost Controls, and Circuit Breaker.

Enforces:
1. Per-tenant daily spending caps with MongoDB persistence.
2. Token usage tracking and pricing calculation per run.
3. Provider error circuit breaker (fast failover to deterministic engine on xAI outages).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger


class CircuitBreaker:
    """Circuit breaker for LLM API providers (xAI/Grok, OpenAI)."""

    def __init__(
        self,
        max_consecutive_failures: int = 5,
        cooldown_seconds: float = 60.0,
    ):
        self.max_failures = max_consecutive_failures
        self.cooldown_seconds = cooldown_seconds
        self.failure_count = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.tripped_at: Optional[datetime] = None
        self._lock = asyncio.Lock()

    async def can_attempt(self) -> bool:
        """Returns True if a request to the LLM is permitted."""
        async with self._lock:
            if self.state == "CLOSED":
                return True

            now = datetime.now(timezone.utc)
            if self.state == "OPEN":
                if self.tripped_at and (now - self.tripped_at).total_seconds() >= self.cooldown_seconds:
                    logger.info("circuit_breaker_half_open_trial")
                    self.state = "HALF_OPEN"
                    return True
                return False

            # In HALF_OPEN, permit single attempt
            return True

    async def record_success(self):
        """Resets the circuit breaker on a successful response."""
        async with self._lock:
            if self.state != "CLOSED":
                logger.info("circuit_breaker_reset_closed")
            self.failure_count = 0
            self.state = "CLOSED"
            self.tripped_at = None

    async def record_failure(self):
        """Records an API failure and opens the circuit if threshold exceeded."""
        async with self._lock:
            self.failure_count += 1
            if self.failure_count >= self.max_failures or self.state == "HALF_OPEN":
                self.state = "OPEN"
                self.tripped_at = datetime.now(timezone.utc)
                logger.warning(
                    "circuit_breaker_tripped_open",
                    consecutive_failures=self.failure_count,
                    cooldown_seconds=self.cooldown_seconds,
                )


class LLMGovernance:
    def __init__(self):
        self.circuit_breaker = CircuitBreaker(
            max_consecutive_failures=settings.LLM_CIRCUIT_BREAKER_MAX_FAILURES,
            cooldown_seconds=float(settings.LLM_CIRCUIT_BREAKER_RESET_SECONDS),
        )

    def calculate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculates estimated cost in USD based on configured token rates."""
        prompt_cost = (prompt_tokens / 1000.0) * settings.LLM_PRICE_PER_1K_PROMPT_TOKENS
        completion_cost = (completion_tokens / 1000.0) * settings.LLM_PRICE_PER_1K_COMPLETION_TOKENS
        return round(prompt_cost + completion_cost, 6)

    async def can_query_llm(self, db, org_id: str) -> Tuple[bool, str]:
        """
        Validates both circuit breaker status and tenant daily spending cap.
        Returns (is_allowed, reason_if_denied).
        """
        # 1. Check Circuit Breaker
        if not await self.circuit_breaker.can_attempt():
            return False, "circuit_breaker_tripped_open"

        # 2. Check Daily Spending Cap
        if db is not None:
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            doc_id = f"usage:{org_id}:{today_str}"
            try:
                usage_doc = await db["llm_usage"].find_one({"_id": doc_id})
                current_spend = float(usage_doc.get("cost_usd", 0.0)) if usage_doc else 0.0
                if current_spend >= settings.LLM_DAILY_TENANT_CAP_USD:
                    logger.warning(
                        "llm_tenant_daily_cap_exceeded",
                        org_id=org_id,
                        current_spend=current_spend,
                        cap=settings.LLM_DAILY_TENANT_CAP_USD,
                    )
                    return False, "tenant_daily_budget_exceeded"
            except Exception as exc:
                logger.debug("llm_governance_budget_check_error", error=str(exc))

        return True, "ok"

    async def record_usage(
        self,
        db,
        org_id: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> Dict[str, Any]:
        """Atomically persists token consumption and spend to MongoDB."""
        cost = self.calculate_cost(prompt_tokens, completion_tokens)
        total_tokens = prompt_tokens + completion_tokens

        usage_data = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": cost,
        }

        if db is not None:
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            doc_id = f"usage:{org_id}:{today_str}"
            try:
                await db["llm_usage"].update_one(
                    {"_id": doc_id},
                    {
                        "$inc": {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": total_tokens,
                            "cost_usd": cost,
                            "request_count": 1,
                        },
                        "$setOnInsert": {
                            "org_id": org_id,
                            "date": today_str,
                            "created_at": datetime.now(timezone.utc),
                        },
                    },
                    upsert=True,
                )
            except Exception as exc:
                logger.debug("llm_usage_record_failed", error=str(exc))

        return usage_data


# Global governance singleton
llm_governance = LLMGovernance()

