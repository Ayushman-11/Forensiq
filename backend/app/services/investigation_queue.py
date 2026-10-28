"""
FairInvestigationQueue – fair, multi-tenant investigation queue with worker autoscaling.

Addresses Limit #6:
  "Auto-investigation concurrency is fixed at 3 per process.
   Fix: Queue with worker autoscaling; per-tenant fairness."

Features:
  - Per-tenant fair scheduling (round-robin dispatch over tenant queues):
    Prevents a burst of alerts from Tenant A from starving alerts from Tenant B.
  - Dynamic worker autoscaling:
    Dynamically scales investigation concurrency between min_workers and max_workers
    proportional to pending backlog, and scales back down when the queue clears.
  - Lifecycle integration:
    Allows poller and test suites to track, gather, and cancel in-flight tasks cleanly.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, Optional, Set

from app.core.config import settings
from app.core.logging import logger


class FairInvestigationQueue:
    def __init__(
        self,
        min_workers: Optional[int] = None,
        max_workers: Optional[int] = None,
        scale_up_threshold: Optional[int] = None,
    ) -> None:
        self.min_workers = min_workers or getattr(
            settings, "INVESTIGATION_MIN_WORKERS", getattr(settings, "INVESTIGATION_CONCURRENCY", 3)
        )
        self.max_workers = max_workers or getattr(settings, "INVESTIGATION_MAX_WORKERS", 10)
        self.scale_up_threshold = scale_up_threshold or getattr(settings, "INVESTIGATION_SCALE_UP_THRESHOLD", 2)

        self._queues: Dict[str, Deque[asyncio.Event]] = {}
        self._active_tenants: Deque[str] = deque()
        self._lock = asyncio.Lock()
        self._active_workers: int = 0
        self._running: bool = True
        self._inflight_tasks: Set[asyncio.Task] = set()

    @property
    def active_workers(self) -> int:
        """Current number of investigations actively executing."""
        return self._active_workers

    @property
    def total_waiting(self) -> int:
        """Total number of alerts waiting in queue across all tenants."""
        return sum(len(q) for q in self._queues.values())

    def tenant_backlog(self, org_id: str) -> int:
        """Total number of alerts waiting in queue for a specific tenant."""
        q = self._queues.get(org_id)
        return len(q) if q else 0

    def current_concurrency_limit(self) -> int:
        """Dynamic concurrency limit based on current backlog."""
        waiting = self.total_waiting
        if waiting > self._active_workers * self.scale_up_threshold:
            # Scale up proportional to backlog up to max_workers
            return min(self.max_workers, max(self.min_workers, self._active_workers + 2))
        return self.min_workers

    def _try_dispatch_locked(self) -> None:
        """Dispatch waiting events up to the dynamic concurrency limit."""
        if not self._running:
            return

        while self._active_tenants:
            # Recompute target concurrency dynamically as items are dispatched
            waiting = sum(len(q) for q in self._queues.values())
            target_limit = (
                min(self.max_workers, max(self.min_workers, self._active_workers + 2))
                if waiting > self._active_workers * self.scale_up_threshold
                else self.min_workers
            )
            if self._active_workers >= target_limit:
                break

            tenant = self._active_tenants.popleft()
            queue = self._queues.get(tenant)
            if not queue:
                continue

            event = queue.popleft()
            if queue:
                self._active_tenants.append(tenant)

            self._active_workers += 1
            event.set()

    async def run_job(
        self,
        alert: dict,
        org_id: str,
        handler: Callable[[dict], Awaitable[None]],
    ) -> None:
        """Wait for fair execution slot, invoke handler, and release slot upon completion."""
        event = asyncio.Event()
        async with self._lock:
            if not self._running:
                return
            if org_id not in self._queues:
                self._queues[org_id] = deque()
            was_empty = len(self._queues[org_id]) == 0
            self._queues[org_id].append(event)
            if was_empty and org_id not in self._active_tenants:
                self._active_tenants.append(org_id)
            self._try_dispatch_locked()

        # Wait until granted a concurrency slot
        await event.wait()

        try:
            await handler(alert)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "investigation_job_failed",
                alert_id=alert.get("_id"),
                org_id=org_id,
                error=str(exc),
            )
        finally:
            async with self._lock:
                self._active_workers = max(0, self._active_workers - 1)
                self._try_dispatch_locked()

    def enqueue(
        self,
        alert: dict,
        org_id: str,
        handler: Callable[[dict], Awaitable[None]],
    ) -> asyncio.Task:
        """Schedule an investigation task tracked by the queue."""
        task = asyncio.create_task(self.run_job(alert, org_id, handler))
        self._inflight_tasks.add(task)
        task.add_done_callback(self._inflight_tasks.discard)
        return task

    async def stop(self) -> None:
        """Cancel waiting and in-flight investigations and release state."""
        async with self._lock:
            self._running = False
            # Wake any waiting events so they can exit/cancel cleanly
            for queue in self._queues.values():
                while queue:
                    ev = queue.popleft()
                    ev.set()
            self._queues.clear()
            self._active_tenants.clear()

        # Cancel running tasks
        tasks = list(self._inflight_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._inflight_tasks.clear()
        self._active_workers = 0
