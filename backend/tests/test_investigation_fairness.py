import asyncio
import pytest

from app.services.investigation_queue import FairInvestigationQueue


@pytest.mark.asyncio
async def test_fair_queue_interleaves_tenants():
    """
    Verify that a flood of alerts from tenant-A does not starve tenant-B.
    Tenant B's alerts must be interleaved fairly.
    """
    queue = FairInvestigationQueue(min_workers=2, max_workers=2, scale_up_threshold=100)
    history = []

    async def mock_handler(alert):
        history.append((alert["org_id"], alert["id"]))
        await asyncio.sleep(0.02)

    tasks = []
    # Tenant A enqueues 10 alerts
    for i in range(10):
        tasks.append(queue.enqueue({"id": i, "org_id": "tenant-A"}, "tenant-A", mock_handler))

    # Tenant B enqueues 2 alerts
    for i in range(2):
        tasks.append(queue.enqueue({"id": i, "org_id": "tenant-B"}, "tenant-B", mock_handler))

    await asyncio.gather(*tasks)

    # First few events must contain tenant-B items rather than all tenant-A items first
    first_four_tenants = [t for t, _ in history[:6]]
    assert "tenant-B" in first_four_tenants, f"Expected tenant-B to be scheduled fairly, got {history}"
    assert len(history) == 12


@pytest.mark.asyncio
async def test_worker_autoscaling_under_backlog():
    """
    Verify concurrency scales up from min_workers to max_workers under heavy backlog.
    """
    min_w = 2
    max_w = 6
    queue = FairInvestigationQueue(min_workers=min_w, max_workers=max_w, scale_up_threshold=1)

    peak_concurrency = 0
    current_concurrency = 0
    lock = asyncio.Lock()

    async def tracking_handler(alert):
        nonlocal peak_concurrency, current_concurrency
        async with lock:
            current_concurrency += 1
            if current_concurrency > peak_concurrency:
                peak_concurrency = current_concurrency
        await asyncio.sleep(0.05)
        async with lock:
            current_concurrency -= 1

    tasks = []
    # Enqueue 15 alerts across 3 tenants
    for i in range(15):
        tenant = f"tenant-{i % 3}"
        tasks.append(queue.enqueue({"id": i, "org_id": tenant}, tenant, tracking_handler))

    await asyncio.gather(*tasks)

    # Concurrency should have autoscaled beyond min_workers
    assert peak_concurrency > min_w, f"Expected peak concurrency > {min_w}, got {peak_concurrency}"
    assert peak_concurrency <= max_w, f"Expected peak concurrency <= {max_w}, got {peak_concurrency}"
    assert queue.active_workers == 0
    assert queue.total_waiting == 0


@pytest.mark.asyncio
async def test_queue_stop_cancels_inflight():
    """Verify that stopping the queue cancels waiting and in-flight investigations."""
    queue = FairInvestigationQueue(min_workers=1, max_workers=2)
    started = asyncio.Event()

    async def slow_handler(alert):
        started.set()
        await asyncio.sleep(10)

    t1 = queue.enqueue({"id": 1}, "tenant-A", slow_handler)
    t2 = queue.enqueue({"id": 2}, "tenant-A", slow_handler)

    await started.wait()
    await queue.stop()

    assert t1.cancelled() or t1.done()
    assert t2.cancelled() or t2.done()
    assert queue.active_workers == 0
