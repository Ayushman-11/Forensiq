# Chapter 4: Multi-Agent AI Pipeline (LangGraph)

The **Multi-Agent AI Pipeline** is the crown jewel of Forensiq. It replaces the traditional 45-minute manual investigation workflow of a human SOC analyst with an autonomous, 7-stage collaborative AI graph built on **LangGraph**.

This chapter explains what each of the 7 agents does, what inputs they take, and what outputs they produce.

---

## 1. What is LangGraph and Why Do We Use It?

In basic AI apps, people often send a single giant prompt to ChatGPT. In cybersecurity, **single-prompt AI fails** because security investigations require strict procedural discipline:
- You cannot score risk until you know if the IP address is malicious.
- You cannot write a playbook until you understand the attack timeline.
- You must verify every step without hallucination.

**LangGraph** solves this by organizing the investigation into a **Directed Acyclic Graph (DAG)** of 7 discrete, specialized AI nodes. Each node performs one job, verifies its data, updates a shared state object (`AgentState`), and passes it to the next specialized node.

```mermaid
graph LR
    Start([Alert Ingested]) --> Node1[1. Context Node]
    Node1 --> Node2[2. Threat Intel Node]
    Node2 --> Node3[3. Correlation Node]
    Node3 --> Node4[4. MITRE Node]
    Node4 --> Node5[5. Timeline Node]
    Node5 --> Node6[6. Risk Node]
    Node6 --> Node7[7. Playbook Node]
    Node7 --> End([Investigation Complete])
```

---

## 2. The 7 Agents Explained in Deep Detail

### Node 1: Context Extraction Agent (`backend/app/agents/context_agent.py`)
- **What it does**: Inspects the raw alert and extracts the structural parameters of the incident.
- **Inputs**: Raw Sysmon/Windows event dictionary.
- **Key Actions**:
  - Parses Windows Event IDs (`1`, `3`, `13`, `22`, `4625`, `4648`, `4688`, `4104`).
  - Extracts the targeted user, process name, parent process name, process ID (PID), full command line arguments, and registry keys.
  - Automatically extracts candidate Indicators of Compromise (IOCs) such as public IP addresses and domain names.
- **Output**: Populates `state["context"]` and `state["extracted_iocs"]`.

---

### Node 2: Threat Intelligence & Enrichment Agent (`backend/app/agents/enrichment_agent.py`)
- **What it does**: Takes the extracted IP addresses, domains, and file hashes, and queries external global threat intelligence databases to check their reputation.
- **External Services Used**:
  - **VirusTotal v3**: Scans hashes, domains, and IPs across 70+ antivirus engines.
  - **AbuseIPDB v2**: Checks IP reputation reports from network administrators worldwide.
- **Intelligence Caching**:
  - To prevent burning through external API rate limits, all lookups are cached in the MongoDB `enrichment_cache` collection for 24 hours.
- **Output**:
  - Assigns an individual reputation tag (`malicious`, `suspicious`, `clean`, or `unknown`).
  - Assigns a numeric threat score from `0` to `100`.
  - Populates `state["enrichments"]`.

---

### Node 3: Cross-Alert Correlation Agent (`backend/app/agents/correlation_agent.py`)
- **What it does**: Hackers rarely stop at one action. They perform reconnaissance, move laterally to another machine, and attempt to dump credentials.
- **Key Actions**:
  - Searches the database for other alerts created in the past 24 hours that share the **same Host**, **same User**, **same Source IP**, or **same Process Name**.
  - Groups related alerts together into an incident cluster so the analyst sees the full campaign rather than isolated incidents.
- **Output**: Populates `state["correlations"]` with matched alert IDs and matching criteria.

---

### Node 4: MITRE ATT&CK Mapping Agent (`backend/app/agents/mitre_agent.py`)
- **What it does**: Classifies the adversary's actions according to the official MITRE ATT&CK Enterprise Matrix framework.
- **Key Actions**:
  - Inspects the command line, event code, and detection rule name.
  - Matches the exact Technique ID (e.g., `T1059.001` for PowerShell, `T1003` for Credential Dumping, `T1071.004` for DNS Tunneling) and parent Tactic (e.g., `Execution`, `Credential Access`, `Lateral Movement`).
  - Populates official MITRE technique names and descriptions.
- **Output**: Populates `state["mitre_technique"]`, `state["mitre_tactic"]`, and `state["mitre_mappings"]`.

---

### Node 5: Timeline Reconstruction Agent (`backend/app/agents/timeline_agent.py`)
- **What it does**: Reconstructs the story of the attack in human-readable chronological order.
- **Why this matters**: Reading raw timestamps in logs is confusing. The timeline agent synthesizes a narrative:
  - *T-00:04s*: Parent process `explorer.exe` spawned target process `powershell.exe`.
  - *T-00:02s*: Encoded command line executed with bypass flags.
  - *T-00:01s*: Reconnaissance tool `whoami.exe /priv` executed.
  - *T-00:00s*: Outbound network connection established to C2 server `194.26.29.112:443`.
- **Output**: Populates `state["timeline"]` with an array of sequential attack events.

---

### Node 6: Quantitative Risk Assessment Agent (`backend/app/agents/risk_agent.py`)
- **What it does**: Calculates an objective mathematical **Risk Score from 0 to 100** and assigns a priority (`P1 - Critical`, `P2 - High`, `P3 - Medium`, `P4 - Low`).
- **Mathematical Formula**:
  The risk score is not a random guess. It uses a weighted formula:
  $$\text{Risk Score} = (0.35 \times \text{Base Severity}) + (0.35 \times \text{Threat Intel Score}) + (0.15 \times \text{Correlation Multiplier}) + (0.15 \times \text{Asset Criticality})$$
- **AI Confidence Score (0–100%)**:
  Calculates how certain the AI is based on evidence completeness (e.g., if external threat intel confirmed the IP + command line was heavily obfuscated, confidence is high: `90%+`).
- **Output**: Populates `state["risk_score"]`, `state["priority"]`, and `state["ai_confidence"]`.

---

### Node 7: Recommendation & Playbook Agent (`backend/app/agents/recommendation_agent.py`)
- **What it does**: Acts as a senior Tier-3 SOC Incident Commander. It generates a clear, actionable incident response playbook tailored to the exact findings.
- **Output Sections**:
  1. **Immediate Containment**: Exact steps to isolate the compromised computer (e.g., *"Isolate host WIN-SRV-01 from the network using EDR agent"*).
  2. **Eradication**: How to remove the malware (e.g., *"Kill PID 4892, delete file C:\temp\payload.bin, clear Registry Run key SecurityAgent"*).
  3. **Credential Remediation**: Which accounts need immediate password resets and session revocations.
  4. **Firewall / Network Blocks**: Exact IP and domain rules to push to edge firewalls.
- **Output**: Populates `state["recommendation"]`.

---

## 3. Real-Time Streaming over WebSockets

When an analyst clicks **"Run Agent Pipeline"** on the frontend, how do they see what is happening?

1. The frontend opens a WebSocket connection to:
   `ws://localhost:8001/api/v1/alerts/{alert_id}/ws`
2. As the backend executes each node in LangGraph, it pushes JSON packets over the socket:
   ```json
   {
     "type": "node_complete",
     "node": "enrichment",
     "step": 2,
     "summary": "VirusTotal identified 194.26.29.112 as Malicious (Confidence: 85/100)",
     "status": "completed"
   }
   ```
3. The frontend modal updates its step-by-step progress bar live, animates the active node, and appends the log message to the terminal console.
4. When Node 7 finishes, the alert status is automatically saved as **"Investigated"**, the WebSocket closes cleanly, and the **PDF Download buttons** unlock.

---

*Next Chapter: [Chapter 5: Threat Intelligence & Enrichment Engine](file:///d:/Forensiq/docs/project_handbook/05_threat_intel_and_enrichment.md)*
