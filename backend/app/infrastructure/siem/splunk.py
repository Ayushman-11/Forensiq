"""
Production-grade Async Splunk REST API Client.
Implements SIEMProvider interface using httpx async client.
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logging import logger
from app.schemas.normalized_event import NormalizedEvent, NormalizedAlert
from app.infrastructure.siem.base import SIEMProvider


class SplunkClient:
    """
    Async Splunk REST API Client supporting session management, search jobs,
    polling, pagination, and normalized data conversion.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        self.base_url = (url or settings.SPLUNK_URL).rstrip("/")
        self.username = username or settings.SPLUNK_USERNAME
        self.password = password or settings.SPLUNK_PASSWORD
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.SPLUNK_VERIFY_SSL
        self.session_key: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy creation of HTTP client with connection pooling and timeouts."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(30.0, connect=10.0),
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        """Closes the underlying HTTP client connection pool."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def authenticate(self) -> bool:
        """Authenticates with Splunk REST API and caches the session key."""
        client = await self._get_client()
        auth_url = f"{self.base_url}/services/auth/login?output_mode=json"
        payload = {"username": self.username, "password": self.password}

        try:
            response = await client.post(auth_url, data=payload)
            response.raise_for_status()
            data = response.json()
            self.session_key = data["sessionKey"]
            logger.info("splunk_auth_success", user=self.username)
            return True
        except Exception as e:
            logger.error("splunk_auth_failed", error=str(e))
            raise RuntimeError(f"Splunk Authentication Failed: {e}")

    async def _headers(self) -> Dict[str, str]:
        """Returns request headers including Splunk session authorization."""
        if not self.session_key:
            await self.authenticate()
        return {
            "Authorization": f"Splunk {self.session_key}",
            "Accept": "application/json",
        }

    async def search(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        limit: int = 100,
    ) -> List[NormalizedEvent]:
        """
        Executes a search query by creating a Splunk Search Job, polling for completion,
        and retrieving results transformed into NormalizedEvent objects.
        """
        # Ensure query starts with search keyword if missing
        clean_query = query.strip()
        if not (clean_query.startswith("search") or clean_query.startswith("|")):
            clean_query = f"search {clean_query}"

        job_id = await self.submit_search(clean_query, earliest_time, latest_time)
        await self.poll_search(job_id)
        raw_results = await self.get_results(job_id, limit=limit)
        return [self._normalize_splunk_event(row) for row in raw_results]

    async def submit_search(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
    ) -> str:
        """Submits an asynchronous search job to Splunk."""
        client = await self._get_client()
        headers = await self._headers()
        jobs_url = f"{self.base_url}/services/search/jobs?output_mode=json"

        # Ensure search query starts with search keyword
        formatted_query = query.strip()
        if not (formatted_query.startswith("search") or formatted_query.startswith("|")):
            formatted_query = f"search {formatted_query}"

        data = {
            "search": formatted_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "exec_mode": "normal",
        }

        response = await client.post(jobs_url, headers=headers, data=data)
        response.raise_for_status()
        job_data = response.json()
        job_id = job_data.get("sid")
        logger.info("splunk_search_submitted", sid=job_id, query=query)
        return job_id

    async def poll_search(self, sid: str, max_wait_seconds: int = 60, poll_interval: float = 0.5) -> bool:
        """Polls Splunk Search Job status until complete or dispatchState is DONE."""
        client = await self._get_client()
        headers = await self._headers()
        status_url = f"{self.base_url}/services/search/jobs/{sid}?output_mode=json"

        elapsed = 0.0
        while elapsed < max_wait_seconds:
            response = await client.get(status_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            entry = data["entry"][0]
            is_done = entry["content"].get("isDone", False)
            dispatch_state = entry["content"].get("dispatchState", "")

            if is_done or dispatch_state == "DONE":
                logger.info("splunk_search_complete", sid=sid, elapsed=round(elapsed, 2))
                return True

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        raise TimeoutError(f"Splunk Search Job {sid} timed out after {max_wait_seconds} seconds")

    async def get_results(self, sid: str, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetches parsed JSON result events from completed Splunk Search Job."""
        client = await self._get_client()
        headers = await self._headers()
        results_url = (
            f"{self.base_url}/services/search/jobs/{sid}/results?output_mode=json"
            f"&count={limit}&offset={offset}"
        )

        response = await client.get(results_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("results", [])

    async def list_alerts(self, limit: int = 50) -> List[NormalizedAlert]:
        """Lists active threat alert rules and fired alerts from Splunk REST API."""
        client = await self._get_client()
        headers = await self._headers()
        alerts: List[NormalizedAlert] = []

        # 1. Query fired_alerts endpoint
        fired_url = f"{self.base_url}/services/alerts/fired_alerts?output_mode=json&count={limit}"
        try:
            resp = await client.get(fired_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entry", []):
                    title = entry.get("name") or "Splunk Alert"
                    if title != "-":
                        alerts.append(
                            NormalizedAlert(
                                alert_id=entry.get("id", ""),
                                title=title,
                                description=entry.get("content", {}).get("description"),
                                severity=entry.get("content", {}).get("severity", "medium"),
                                created_at=datetime.now(timezone.utc),
                                source_siem="splunk",
                                raw_alert_data=entry,
                            )
                        )
        except Exception as e:
            logger.error("splunk_fired_alerts_error", error=str(e))

        # 2. Query saved searches configured as detection rules
        saved_url = f"{self.base_url}/servicesNS/{self.username.lower()}/search/saved/searches?output_mode=json&search=name%3DForensiq_*&count={limit}"
        try:
            resp = await client.get(saved_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entry", []):
                    name = entry.get("name", "")
                    content = entry.get("content", {})
                    
                    # Human Readable Metadata Mapping
                    if "PowerShell" in name:
                        title = "[CRITICAL] Suspicious PowerShell Execution & Cradles"
                        desc = "Detected suspicious PowerShell command execution or encoded payload cradle. Potential execution phase of attack."
                        severity = "critical"
                        mitre = ["T1059.001 (Command and Scripting Interpreter: PowerShell)"]
                    elif "Registry" in name:
                        title = "[HIGH] Persistence via Windows Registry Run Keys"
                        desc = "Modification detected in Windows CurrentVersion\\Run registry persistence keys."
                        severity = "high"
                        mitre = ["T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)"]
                    elif "Login" in name or "Authentication" in name or "Brute Force" in name:
                        title = "[HIGH] Multiple Failed Login Attempts"
                        desc = "Unusual volume of failed authentication attempts indicating potential brute force."
                        severity = "high"
                        mitre = ["T1110 (Brute Force)"]
                    elif "Nmap" in name or "Port Scan" in name or "Scan" in name:
                        title = "[MEDIUM] Network Port Scanning Detected (Nmap)"
                        desc = "High frequency of connections to multiple ports on a single host or multiple hosts."
                        severity = "medium"
                        mitre = ["T1046 (Network Service Discovery)"]
                    elif "Network" in name or "Discovery" in name or "Host" in name:
                        title = "[MEDIUM] Network & System Reconnaissance Discovery"
                        desc = "Execution of system discovery commands or sweeping IP ranges for active hosts."
                        severity = "medium"
                        mitre = ["T1018 (Remote System Discovery)", "T1087 (Account Discovery)"]
                    else:
                        title = name.replace("Forensiq_Alert_", "").replace("_", " ")
                        desc = content.get("search", "")
                        severity = "medium"
                        mitre = []

                    alerts.append(
                        NormalizedAlert(
                            alert_id=entry.get("id", name),
                            title=title,
                            description=desc,
                            severity=severity,
                            created_at=datetime.now(timezone.utc),
                            source_siem="splunk",
                            mitre_techniques=mitre,
                            raw_alert_data=entry,
                        )
                    )
        except Exception as e:
            logger.error("splunk_saved_searches_alerts_error", error=str(e))

        return alerts

    async def list_indexes(self) -> List[str]:
        """Lists available indexes in Splunk."""
        client = await self._get_client()
        headers = await self._headers()
        indexes_url = f"{self.base_url}/services/data/indexes?output_mode=json&count=0"

        response = await client.get(indexes_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [entry["name"] for entry in data.get("entry", [])]

    async def create_dashboard(self, name: str, label: str, xml_definition: str) -> bool:
        """
        Creates or updates a Dashboard view in Splunk using REST API /servicesNS/{user}/search/data/ui/views.
        """
        client = await self._get_client()
        headers = await self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        views_url = f"{self.base_url}/servicesNS/{self.username}/search/data/ui/views?output_mode=json"

        data = {
            "name": name,
            "eai:data": xml_definition,
        }

        try:
            response = await client.post(views_url, headers=headers, data=data)
            if response.status_code in (200, 201):
                logger.info("splunk_dashboard_created", name=name)
                return True
            elif response.status_code == 409 or "already exists" in response.text.lower():
                # Dashboard exists, update it
                update_url = f"{self.base_url}/servicesNS/{self.username}/search/data/ui/views/{name}?output_mode=json"
                update_resp = await client.post(update_url, headers=headers, data={"eai:data": xml_definition})
                update_resp.raise_for_status()
                logger.info("splunk_dashboard_updated", name=name)
                return True
            else:
                logger.error("splunk_dashboard_error_body", body=response.text)
                response.raise_for_status()
                return True
        except Exception as e:
            logger.error("splunk_dashboard_create_failed", name=name, error=str(e))
            raise RuntimeError(f"Failed to create Splunk dashboard '{name}': {e}")

    async def create_saved_search(
        self,
        name: str,
        search_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        cron_schedule: str = "*/1 * * * *",
    ) -> bool:
        """
        Creates a Saved Search / Alert rule in Splunk for continuous threat detection.
        """
        client = await self._get_client()
        headers = await self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        saved_searches_url = f"{self.base_url}/servicesNS/{self.username}/search/saved/searches?output_mode=json"

        # Ensure search query starts with search keyword
        clean_query = search_query.strip()
        if not (clean_query.startswith("search") or clean_query.startswith("|")):
            clean_query = f"search {clean_query}"

        data = {
            "name": name,
            "search": clean_query,
            "dispatch.earliest_time": earliest_time,
            "dispatch.latest_time": latest_time,
            "is_scheduled": "1",
            "cron_schedule": cron_schedule,
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.track": "1",
            "alert.severity": "3",
            "actions": "email",
            "action.email.to": "admin@forensiq.ai",
        }

        try:
            response = await client.post(saved_searches_url, headers=headers, data=data)
            if response.status_code in (200, 201):
                logger.info("splunk_saved_search_created", name=name)
                return True
            else:
                # Already exists, update query and alert tracking properties
                update_url = f"{self.base_url}/servicesNS/{self.username}/search/saved/searches/{name}?output_mode=json"
                update_data = {
                    "search": clean_query,
                    "is_scheduled": "1",
                    "cron_schedule": cron_schedule,
                    "alert.track": "1",
                    "alert_type": "number of events",
                    "alert_comparator": "greater than",
                    "alert_threshold": "0",
                    "actions": "email",
                    "action.email.to": "admin@forensiq.ai",
                }
                update_resp = await client.post(update_url, headers=headers, data=update_data)
                update_resp.raise_for_status()
                logger.info("splunk_saved_search_updated", name=name)
                return True
        except Exception as e:
            logger.error("splunk_saved_search_failed", name=name, error=str(e))
            raise RuntimeError(f"Failed to create saved search '{name}': {e}")

    async def trigger_saved_search(self, name: str) -> str:
        """
        Manually dispatches a Saved Search in Splunk so it fires an alert.
        """
        client = await self._get_client()
        headers = await self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        dispatch_url = f"{self.base_url}/servicesNS/{self.username}/search/saved/searches/{name}/dispatch?output_mode=json"

        try:
            response = await client.post(dispatch_url, headers=headers, data={"trigger_actions": "1"})
            response.raise_for_status()
            data = response.json()
            sid = data.get("sid") or data.get("entry", [{}])[0].get("name", "")
            logger.info("splunk_saved_search_triggered", name=name, sid=sid)
            return sid
        except Exception as e:
            logger.error("splunk_trigger_saved_search_failed", name=name, error=str(e))
            raise RuntimeError(f"Failed to trigger saved search '{name}': {e}")

    def _parse_message_kv(self, message: str) -> Dict[str, str]:
        """Extracts key-value pairs from Sysmon Message text block."""
        kv = {}
        if not message:
            return kv
        for line in message.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                kv[key.strip()] = value.strip()
        return kv

    def _normalize_splunk_event(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Transforms raw Splunk JSON result into NormalizedEvent model."""
        # Extract parsed key-values from Message string if present
        msg_kv = self._parse_message_kv(raw.get("Message", ""))

        # Helper getter prioritising top-level Splunk fields, then Message KV block
        def get_field(key: str) -> Optional[str]:
            val = raw.get(key)
            if val is not None and str(val) != "":
                return str(val)
            return msg_kv.get(key)

        # Parse timestamp
        raw_time = raw.get("_time")
        event_time = datetime.now(timezone.utc)
        if raw_time:
            try:
                event_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except Exception:
                pass

        pid_val = get_field("ProcessId")
        parent_pid_val = get_field("ParentProcessId")

        return NormalizedEvent(
            timestamp=event_time,
            event_id=str(get_field("EventCode") or raw.get("event_id") or "0"),
            provider=str(raw.get("source") or raw.get("sourcetype") or "Splunk"),
            hostname=str(raw.get("host") or get_field("ComputerName") or "unknown"),
            user=get_field("user") or get_field("User") or get_field("Account_Name"),
            domain=get_field("domain") or get_field("Account_Domain"),
            process_name=get_field("process_name") or get_field("Image"),
            command_line=get_field("command_line") or get_field("CommandLine"),
            parent_process_name=get_field("parent_process") or get_field("ParentImage"),
            parent_command_line=get_field("ParentCommandLine"),
            process_id=int(pid_val) if pid_val and pid_val.isdigit() else None,
            parent_process_id=int(parent_pid_val) if parent_pid_val and parent_pid_val.isdigit() else None,
            source_ip=get_field("src_ip") or get_field("SourceIp"),
            destination_ip=get_field("dest_ip") or get_field("DestinationIp"),
            destination_port=int(get_field("dest_port")) if get_field("dest_port") and get_field("dest_port").isdigit() else None,
            registry_target_object=get_field("TargetObject"),
            registry_details=get_field("Details"),
            raw_payload=raw,
        )
