# Chapter 8: Concrete Real-World Walkthrough Example

To truly understand Forensiq, it helps to follow a **single real-world cyberattack** from start to finish. 

This chapter walks through a real incident: **An attacker attempts to steal credentials using an encoded PowerShell script and beacon to a Command & Control (C2) server**.

---

## The Attack Scenario

1. **Target**: Server `WIN-SRV-01` owned by user `Administrator`.
2. **Attacker's Action**: 
   - Attacker gains access and opens a command shell.
   - Attacker runs a malicious encoded PowerShell command designed to download a backdoor and dump credentials.
   - The command connects out to malicious IP `194.26.29.112:443`.

---

## Step 1: Ingestion & Detection (Time: 00:00s)

1. Windows Sysmon logs event **Event ID 1 (Process Creation)**:
   - `Image`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   - `CommandLine`: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...`
   - `ParentImage`: `C:\Windows\explorer.exe`
2. Splunk Enterprise indexes this event in `index=attack_data`.
3. Forensiq's background poller queries Splunk via REST API and pulls the raw log.
4. Forensiq evaluates the 8 detection rules:
   - Rule `encoded_powershell` matches!
   - Severity is tagged as **CRITICAL**.
5. Alert `6712ab4f8902cd1138a091e2` is created in MongoDB with Status: **"New"**.
6. The alert appears instantly on the Forensiq Dashboard under **"New Detections Pending Triage"**.

---

## Step 2: The SOC Analyst Clicks "Run Agent Pipeline" (Time: 00:02s)

The analyst clicks on the alert and clicks the primary button: **"Run Agent Pipeline"**.
The `InvestigationModal` opens, opens a WebSocket connection to the backend, and displays the 7-node pipeline.

---

## Step 3: Multi-Agent AI Investigation in Action (Time: 00:03s – 00:09s)

```
[WebSocket Event Stream]
00:03s -> [Node 1: Context]     Extracted Host: WIN-SRV-01, User: Administrator, Target: powershell.exe (PID: 4892)
00:04s -> [Node 2: Threat Intel] Scanned IP 194.26.29.112: VirusTotal flag (58/72 engines malicious, Score: 85/100)
00:05s -> [Node 3: Correlation]  Correlated with 2 earlier failed logon attempts from same IP address
00:06s -> [Node 4: MITRE ATT&CK] Classified as T1059.001 (PowerShell Execution) under Tactic TA0002 (Execution)
00:07s -> [Node 5: Timeline]     Constructed 4-stage chronology: Spawn -> Bypass Enc -> Recon -> C2 Beacon
00:08s -> [Node 6: Risk]         Calculated Risk Score: 88/100 | Priority: P1 (Critical) | AI Confidence: 95%
00:09s -> [Node 7: Playbook]     Synthesized 4-part containment & eradication response plan
```

Investigation completes in **6.4 seconds**. Alert status transitions to **"Investigated"**.

---

## Step 4: Visualizing the Attack in the UI (Time: 00:10s)

Now, the analyst inspects the investigation workbench:

### 1. In the MITRE ATT&CK Matrix:
- Column **Execution (`TA0002`)** &rarr; Cell **PowerShell (`T1059.001`)** glows bright red with the badge `42 hits`.
- The analyst clicks the cell to open the drilldown drawer and confirm other matching incidents.

### 2. In the Visual Process Execution Tree:
The SVG graph displays the exact parent-child hierarchy:
- **Root Node**: `explorer.exe` (PID: 1044, Benign).
- **Connecting Stem**: Pulsing red indicator down to...
- **Execution Node**: `powershell.exe` (PID: 4892, Malicious).
- **Dual Connecting Branches**:
  - Left Branch &rarr; `whoami.exe` (PID: 5012, Privilege Discovery `T1033`).
  - Center Branch &rarr; `C2 Beacon: 194.26.29.112:443` (Active TLS Outbound `T1071.001`).
  - Right Branch &rarr; `Dropped Artifact: payload.bin` (Sysmon Event 11).
- The analyst clicks **"Play Execution"**: the graph animates each stage chronologically, simulating the exact attack flow.
- The analyst clicks **"Copy"** next to the command line to preserve the payload for reverse engineering.

### 3. In the Threat Intel Hover Card:
- Hovering over `194.26.29.112` reveals the defanged box: `194.26.29[.]112`.
- Displays the **VirusTotal link** and **Pivot to SPL** shortcut.

---

## Step 5: Exporting the Branded PDF Report (Time: 00:15s)

The analyst needs to brief the CISO before a management meeting in 10 minutes:

1. In the top right corner of the investigation screen, the analyst clicks **"Exec PDF"**.
2. The browser makes an authenticated call to `/api/v1/alerts/6712ab4f8902cd1138a091e2/report/pdf?report_type=executive`.
3. ReportLab on the server instantly compiles the 1-page executive dossier:
   - **Header**: Official Forensiq Security Operations seal.
   - **Metrics**: Risk Score `88/100`, Priority `P1 - Critical`, Status `Investigated`.
   - **Executive Verdict**: Clear, plain-English summary explaining that an unauthorized encoded PowerShell script attempted to establish an encrypted C2 beacon to a known malicious IP.
   - **Action Items**: Isolate host `WIN-SRV-01`, kill PID `4892`, block `194.26.29.112` on the perimeter firewall.
4. The PDF automatically downloads to the analyst's laptop as `forensiq_executive_summary_6712ab4f.pdf`.

**Total time elapsed**: Under 30 seconds. A human doing this manually would have taken 45 minutes.

---

*Next Chapter: [Chapter 9: Glossary & Interview / Demo Q&A](file:///d:/Forensiq/docs/project_handbook/09_glossary_and_interview_qa.md)*
