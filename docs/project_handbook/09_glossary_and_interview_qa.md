# Chapter 9: Glossary & Interview / Demo Q&A

This final chapter equips you with **plain-English definitions of cybersecurity jargon** and **ready-to-use answers** for any interview, client demonstration, or presentation about Forensiq.

---

## 1. Cybersecurity Glossary for Beginners

| Term | Simple Definition | Role in Forensiq |
|---|---|---|
| **SOC (Security Operations Center)** | The team and control room responsible for monitoring, detecting, and responding to cyber threats across a company. | Forensiq is the automated AI platform used by SOC teams. |
| **SIEM (Security Information & Event Management)** | A centralized system that collects, aggregates, and stores activity logs from across the enterprise (e.g., Splunk). | Forensiq connects to Splunk via its REST API to pull raw logs. |
| **Alert** | A notification that a specific suspicious event or violation of a detection rule occurred. | Stored in MongoDB; investigated by the AI multi-agent pipeline. |
| **IOC (Indicator of Compromise)** | Forensic evidence left behind by an attacker (malicious IP, domain, or file hash). | Extracted by Agent 1 and checked against VirusTotal/AbuseIPDB by Agent 2. |
| **TTP (Tactics, Techniques, and Procedures)** | The behavioral patterns, methods, and goals of a cyber adversary. | Mapped to the MITRE ATT&CK Matrix by Agent 4. |
| **MITRE ATT&CK** | An open-source, globally recognized matrix categorizing all known adversary behaviors into Tactics and Techniques. | Displayed as an interactive 10-tactic Heatmap on the Forensiq Dashboard. |
| **Sysmon (System Monitor)** | A free Microsoft Windows tool that logs detailed activity (Process creation = Event 1, Network = Event 3, Registry = Event 13, DNS = Event 22). | The primary log format ingested by Forensiq. |
| **C2 (Command and Control)** | A server run by an attacker used to send commands to compromised computers and exfiltrate stolen data. | Visualized as outbound network beacon nodes in the Process Tree Graph. |
| **Defanging** | Modifying malicious links or IPs (e.g. `hxxp[://]` or `[.]`) so they cannot be accidentally clicked. | Implemented in `defang.ts` and rendered inside `<IocHoverCard />`. |
| **Process Tree (DAG)** | A graph showing parent and child relationships of executing computer programs. | Rendered in the Investigation Workbench using dynamic SVG connectors. |
| **Payload** | The actual malicious code or executable dropped or run by an attacker. | Identified in the execution and artifact nodes of the Process Tree. |
| **LOLBins (Living off the Land)** | Legitimate, built-in operating system tools (like `powershell.exe`, `certutil.exe`) abused by hackers. | Monitored by Forensiq detection rules. |
| **Lease Locking** | A concurrency pattern ensuring only one backend worker queries the database/SIEM at a time. | Prevents duplicate alerts and split-brain processing via `lease.py`. |
| **WebSockets** | A continuous, two-way network connection allowing the server to push updates to the browser instantly. | Powers the real-time agent execution stream in the `InvestigationModal`. |
| **ReportLab** | A high-performance Python library used to compile binary PDF documents from code. | Generates Forensiq's 1-page Executive Summaries and full technical reports. |

---

## 2. Frequently Asked Questions (Interview & Demo Cheatsheet)

### Q1: "What is Forensiq and what problem does it solve?"
> **Answer**:  
> "Forensiq is an Autonomous AI-Agent driven Security Operations platform. Today, enterprise SOC teams are overwhelmed by thousands of security alerts daily, and investigating a single alert manually takes 20 to 45 minutes. Forensiq automates this entire lifecycle: it ingests logs from Splunk, filters out benign noise, uses a 7-agent LangGraph pipeline to investigate the incident in under 10 seconds, displays interactive MITRE ATT&CK heatmaps and process execution DAG trees, and compiles downloadable executive PDF reports."

---

### Q2: "Why did you use LangGraph instead of a simple ChatGPT prompt?"
> **Answer**:  
> "Single-prompt LLMs fail in cybersecurity because security investigations require strict procedural discipline. An LLM cannot accurately score risk until it has checked external threat intelligence and correlated related events across the network. By using LangGraph, we break the investigation into 7 discrete, deterministic state-machine nodes: Context, Threat Intel, Correlation, MITRE mapping, Timeline reconstruction, Risk scoring, and Playbook recommendation. Each node verifies its data before passing state to the next."

---

### Q3: "How does Forensiq avoid false alarms and alert fatigue?"
> **Answer**:  
> "We implement a two-layer normalization engine. First, an automated noise filter evaluates incoming logs against known harmless administrative traffic (like Windows Update or internal health checks) and discards them. Second, an intelligent time-window deduplication algorithm combines repeated events with the same signature (like 500 failed logins in 60 seconds) into a single consolidated alert document with a count property, reducing alert volume by over 95%."

---

### Q4: "How does the MITRE ATT&CK Heatmap work in the frontend?"
> **Answer**:  
> "Our MITRE Matrix is an interactive 10-tactic enterprise heatmap connected directly to our backend aggregation API. Each cell represents a specific adversary technique (like PowerShell execution or OS Credential Dumping) and dynamically lights up according to detection frequency: Red for high volume (20+ hits), Amber for medium volume, and Blue for active hits. Analysts can filter to view 'Active Hits Only' or click any cell to drill into matching alerts."

---

### Q5: "How does the Process Execution Tree work? Is it hardcoded?"
> **Answer**:  
> "No, it is completely dynamic. The component inspects the alert's event code, detection rule, and attack category. If the attack is Lateral Movement, it draws a lineage from `winlogon.exe` to `splunkd.exe` with dual explicit credential and worker session nodes. If it's DNS Tunneling, it draws an `svchost.exe` lineage to `nslookup.exe` with query exfiltration nodes. The connecting SVG branch paths and card grids dynamically recalculate based on child node counts."

---

### Q6: "How does Forensiq handle real-time streaming to the browser?"
> **Answer**:  
> "When an analyst clicks 'Run Agent Pipeline', the Next.js frontend establishes a WebSocket connection (`ws://.../ws`) to our FastAPI backend. As each of the 7 LangGraph nodes completes, the server pushes JSON status packets, updating the progress bar and terminal logs in real-time. If the client is behind a restrictive corporate firewall that blocks WebSockets, our system automatically falls back to Server-Sent Events (SSE) within 4 seconds without failing."

---

### Q7: "Why did you choose ReportLab for PDF generation instead of browser print?"
> **Answer**:  
> "Browser printing (`window.print()`) creates inconsistent styling across different browsers, cuts tables in half across page breaks, and includes messy browser margins and URLs. Using ReportLab on the server allows us to compile pixel-perfect, branded binary PDF files directly from Python. We generate both 1-page Executive Summaries for CISOs and multi-page comprehensive technical dossiers for forensic teams with one click."

---

### Q8: "What is the test coverage and reliability of the platform?"
> **Answer**:  
> "The platform is validated by an automated test suite of **329 backend unit and integration tests** passing with a 100% pass rate in `pytest`. The frontend is written in TypeScript and verified with **zero compilation errors** (`npx tsc --noEmit`). Furthermore, we verified the full end-to-end pipeline against a live Splunk Enterprise instance with real Sysmon telemetry."

---

## 3. Summary Cheatsheet for Quick Reference

```
+------------------------------------------------------------------------------------+
|                                 FORENSIQ AT A GLANCE                               |
+------------------------------------------------------------------------------------+
| Core Purpose:    Autonomous AI Security Operations Platform                        |
| Backend:         FastAPI (Python 3.11), Pydantic, Motor (Async MongoDB)             |
| AI Engine:       LangGraph, LangChain, Google Gemini / OpenAI LLM                  |
| SIEM Provider:   Splunk Enterprise (REST API on port 8089)                         |
| Threat Intel:    VirusTotal v3 + AbuseIPDB v2 (MongoDB cached)                     |
| Frontend:        Next.js 14 (App Router), TypeScript, Tailwind CSS                  |
| Real-time Push:  WebSockets (bidirectional) + automatic SSE fallback               |
| Reporting:       ReportLab Server-Side Binary PDFs (Executive & Technical)         |
| SOC Visuals:     MITRE ATT&CK 10-Tactic Heatmap + Dynamic Process DAG Tree         |
| Testing Status:  329 / 329 passing tests (100%) + 0 TypeScript errors              |
+------------------------------------------------------------------------------------+
```

---

*End of Handbook. You can navigate back to the [Master Documentation Index](file:///d:/Forensiq/docs/project_handbook/README.md) at any time.*
