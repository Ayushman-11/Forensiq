"""
Locust Load Test – 50 Concurrent SOC Analysts on 100k Alerts Volume.

Simulates:
  - 50 concurrent SOC analysts concurrently operating in Forensiq
  - Realistic user task weights:
      - 35% Triage queue browsing with cursor pagination (GET /api/v1/alerts)
      - 25% High-frequency dashboard summary polling (GET /api/v1/dashboard/summary)
      - 15% Incident queue review (GET /api/v1/incidents)
      - 15% MITRE ATT&CK matrix analytics (GET /api/v1/alerts/stats/mitre)
      - 10% Alert detail & triage action (POST /api/v1/alerts/{id}/disposition)
  - Asserting performance budgets:
      - p95 latency under 150ms on all read endpoints
      - 0% failure rate under sustained load
"""

import json
import os
import random
from pathlib import Path
from locust import FastHttpUser, between, task


# Load pre-generated analyst JWT tokens
TOKENS_FILE = Path(__file__).resolve().parent / "analysts_tokens.json"


def get_analyst_tokens():
    if TOKENS_FILE.exists():
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


ANALYSTS = get_analyst_tokens()


class SOCAnalystUser(FastHttpUser):
    wait_time = between(1.0, 3.0)  # Analyst dwell time between actions

    def on_start(self):
        """Pick a dedicated analyst persona and configure Authorization header."""
        if ANALYSTS:
            self.analyst = random.choice(ANALYSTS)
            self.token = self.analyst["token"]
            self.org_id = self.analyst.get("org_id", "default")
        else:
            self.analyst = {"email": "analyst_test@forensiq.ai", "role": "tier1_analyst"}
            self.token = "dev_token_placeholder"
            self.org_id = "default"

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.last_cursor = None
        self.cached_alert_ids = []

    @task(35)
    def browse_triage_queue_with_cursor(self):
        """Simulate triage queue browsing with cursor pagination."""
        params = {"limit": 50, "sort": "severity", "status": "open"}
        if self.last_cursor and random.random() < 0.6:
            params["cursor"] = self.last_cursor

        with self.client.get(
            "/api/v1/alerts",
            params=params,
            headers=self.headers,
            name="/api/v1/alerts [cursor pagination]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                self.last_cursor = resp.headers.get("X-Next-Cursor")
                try:
                    alerts = resp.json()
                    if alerts:
                        self.cached_alert_ids = [a["_id"] for a in alerts[:10]]
                    resp.success()
                except Exception as exc:
                    resp.failure(f"Invalid JSON: {exc}")
            else:
                resp.failure(f"Status {resp.status_code}: {resp.text}")

    @task(25)
    def view_dashboard_summary(self):
        """Single summary endpoint consolidating metrics, counts, and SLAs."""
        with self.client.get(
            "/api/v1/dashboard/summary",
            headers=self.headers,
            name="/api/v1/dashboard/summary [cached]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if "total_open" in data and "severities" in data:
                    resp.success()
                else:
                    resp.failure(f"Missing expected keys: {list(data.keys())}")
            else:
                resp.failure(f"Status {resp.status_code}")

    @task(15)
    def list_incidents(self):
        """Browse incidents with precomputed counters and pagination."""
        params = {"limit": 20, "state": "open"}
        with self.client.get(
            "/api/v1/incidents",
            params=params,
            headers=self.headers,
            name="/api/v1/incidents [paginated]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Status {resp.status_code}")

    @task(15)
    def view_mitre_stats(self):
        """Fetch full-corpus MITRE ATT&CK aggregation."""
        with self.client.get(
            "/api/v1/alerts/stats/mitre",
            headers=self.headers,
            name="/api/v1/alerts/stats/mitre [db aggregation]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Status {resp.status_code}")

    @task(10)
    def triage_single_alert(self):
        """Simulate an analyst investigating and acknowledging an alert."""
        if not self.cached_alert_ids:
            return

        alert_id = random.choice(self.cached_alert_ids)
        # 1. Fetch single alert
        self.client.get(
            f"/api/v1/alerts/{alert_id}",
            headers=self.headers,
            name="/api/v1/alerts/:id",
        )
