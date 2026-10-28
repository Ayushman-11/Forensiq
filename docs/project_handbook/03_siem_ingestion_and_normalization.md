# Chapter 3: SIEM Ingestion & Normalization Engine

Before any AI agent can investigate an incident, Forensiq must pull raw logs from enterprise infrastructure, clean them, eliminate false alarms, and organize them into standardized alerts. 

This chapter explains how the **Ingestion & Normalization Engine** works step-by-step.

---

## 1. Connecting to Splunk Enterprise

Forensiq implements a formal `SIEMProvider` protocol in Python ([`backend/app/infrastructure/siem/splunk.py`](file:///d:/Forensiq/backend/app/infrastructure/siem/splunk.py)). 

### The Splunk REST API Workflow:
1. **Authentication**: Forensiq connects to Splunk via HTTPS (`https://localhost:8089/services/auth/login`) using the credentials defined in `.env` (`SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`). Splunk returns an authentication session token.
2. **Job Dispatch**: When searching for new events, Forensiq creates a search job (`POST /services/search/jobs`) with an asynchronous search query (e.g., `search index=attack_data earliest=-1h`).
3. **Status Polling**: Forensiq polls the job's dispatch status (`GET /services/search/jobs/{sid}`) until `isDone=1`.
4. **Result Streaming**: Forensiq streams back JSON-formatted search results in batches to avoid high memory spikes.

---

## 2. The 8 Built-in Threat Detection Rules

When logs arrive from Splunk, Forensiq evaluates them against **8 pre-configured detection rules** ([`backend/app/services/detection_rules.py`](file:///d:/Forensiq/backend/app/services/detection_rules.py)):

| Rule Name | Severity | What It Detects | Example Attack Behavior |
|---|---|---|---|
| `encoded_powershell` | **CRITICAL** | PowerShell executed with base64 encoded or bypass arguments (`-enc`, `-encodedcommand`, `-exec bypass`, `-nop`). | Hacker running an obfuscated script to evade antivirus. |
| `credential_dumping` | **CRITICAL** | Suspicious processes touching LSASS memory (`mimikatz`, `procdump`, `comsvcs.dll`). | Dumping Windows password hashes from RAM. |
| `brute_force_logon` | **HIGH** | High-frequency Windows Event ID 4625 (Failed Logon) from a single IP or user account. | Automated password spraying or dictionary attack. |
| `lateral_movement` | **HIGH** | Windows Event ID 4648 (Logon with Explicit Credentials) or remote service execution (PsExec, RPC). | Hacker hopping from a compromised desktop to a domain controller. |
| `suspicious_network_connection` | **MEDIUM** | Outbound network connection (Sysmon Event 3) on non-standard ports or suspicious destination IPs. | Malware establishing a reverse shell or beaconing home. |
| `dns_tunneling` | **MEDIUM** | Sysmon Event 22 (DNS query) with unusually long subdomains or abnormal query rates. | Smuggling data out through DNS requests without using HTTP. |
| `registry_persistence` | **MEDIUM** | Sysmon Event 13 (Registry modification) modifying Windows Startup Run keys (`Run`, `RunOnce`). | Malware ensuring it automatically relaunches whenever the PC reboots. |
| `process_creation_anomaly` | **LOW** | Living-off-the-land binaries (LOLBins) like `certutil.exe`, `bitsadmin.exe`, or `mshta.exe` executed abnormally. | Using built-in Windows tools to secretly download malicious files. |

---

## 3. Data Normalization: Canonical Events

Raw logs from different systems look completely different:
- A Windows Event 4688 calls the executable `NewProcessName`.
- A Sysmon Event 1 calls the executable `Image`.
- A Linux auditd log calls it `comm` or `exe`.

If Forensiq had to write custom code for every log type, it would be fragile and messy. Instead, Forensiq converts all raw incoming logs into a single **Canonical Event Model** ([`backend/app/schemas/normalized_event.py`](file:///d:/Forensiq/backend/app/schemas/normalized_event.py)):

```python
class CanonicalEvent(BaseModel):
    event_id: str
    event_code: Optional[str]        # e.g., "1", "4625", "22"
    source_type: str                 # e.g., "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    timestamp: datetime
    host: Optional[str]              # e.g., "WIN-SRV-01"
    user: Optional[str]              # e.g., "NT AUTHORITY\\SYSTEM"
    process_name: Optional[str]      # e.g., "powershell.exe"
    process_path: Optional[str]      # e.g., "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    parent_process_name: Optional[str]# e.g., "explorer.exe"
    process_id: Optional[int]        # e.g., 4892
    parent_process_id: Optional[int] # e.g., 1044
    command_line: Optional[str]      # Full execution command
    source_ip: Optional[str]         # IP address
    dest_ip: Optional[str]           # IP address
    dest_port: Optional[int]         # Port number (e.g., 443, 445)
    protocol: Optional[str]          # TCP, UDP
    registry_key: Optional[str]      # Registry path modified
    dns_query: Optional[str]         # Domain queried
```

---

## 4. Noise Reduction & Deduplication

In production environments, thousands of harmless events happen every minute. Forensiq applies two layers of filtering:

### Layer 1: Noise Filtering (`backend/app/normalization/noise.py`)
- Forensiq maintains an intelligent suppression filter for known harmless patterns:
  - Benign Windows update services (`TrustedInstaller.exe`, `TiWorker.exe`).
  - Standard internal corporate domain lookups (e.g., `*.microsoft.com`, `*.windowsupdate.com`).
  - Legitimate health-check network pings between internal cluster nodes.
- If an incoming event matches a known noise rule, it is discarded immediately, saving processing power and storage.

### Layer 2: Time-Window Deduplication (`backend/app/normalization/dedup.py`)
- If a brute-force attacker attempts 500 logins within 60 seconds, Forensiq **does not** create 500 alerts.
- Instead, it generates a hash key combining `(host, user, rule_name, source_ip)`.
- It collapses those 500 events into **one single Alert** with:
  - `count: 500`
  - `first_seen`: Timestamp of attempt 1
  - `last_seen`: Timestamp of attempt 500
- This reduces alert fatigue by over **98%**.

---

## 5. Output: The Normalized Alert Record

Once an event passes the detection rules and noise filters, it is saved into the MongoDB `alerts` collection as an **Alert Record** ([`backend/app/models/alert.py`](file:///d:/Forensiq/backend/app/models/alert.py)).

Here is what an Alert Document looks like in JSON:

```json
{
  "_id": "6712ab4f8902cd1138a091e2",
  "title": "[CRITICAL] Encoded PowerShell Execution Detected on WIN-SRV-01",
  "severity": "critical",
  "status": "New",
  "host": "WIN-SRV-01",
  "user": "Administrator",
  "rule_name": "encoded_powershell",
  "mitre_technique": "T1059.001",
  "mitre_tactic": "Execution",
  "event_code": "1",
  "process_name": "powershell.exe",
  "parent_process": "explorer.exe",
  "command_line": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Enc JABjAGwAaQBl...",
  "extracted_iocs": [
    "194.26.29.112",
    "update-c2.cloud"
  ],
  "count": 1,
  "created_at": "2026-10-22T19:30:00Z"
}
```

At this stage, the alert is visible in the UI with status **"New"**. Now, the multi-agent AI pipeline can take over and investigate it.

---

*Next Chapter: [Chapter 4: Multi-Agent AI Pipeline (LangGraph)](file:///d:/Forensiq/docs/project_handbook/04_multi_agent_investigation_pipeline.md)*
