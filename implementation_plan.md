# Forensiq — Phase 1 & 2 Implementation Plan

> **Goal**: Establish the attack simulation → telemetry → detection → investigation data pipeline, then build the backend that consumes it.

---

## Architectural Context

Before touching any code, let me explain *why* Phase 1 matters architecturally.

Forensiq's value proposition is **evidence-based investigation**. Evidence comes from telemetry. Telemetry comes from detections. Detections come from attacks. If we build the backend first without real telemetry flowing through, we'll be designing schemas and services against imaginary data — the #1 cause of impedance mismatch in security tooling.

```
Phase 1 establishes this data pipeline:

Atomic Red Team (Attack Simulation)
        │
        ▼
Sysmon + Windows Event Logs (Telemetry Generation)
        │
        ▼
Splunk Universal Forwarder (Collection)
        │
        ▼
Splunk Enterprise (Indexing + Detection)
        │
        ▼
Forensiq Backend (Phase 2 — Ingestion + Investigation)
```

**Phase 1 ensures**: when we write our `SplunkClient`, `NormalizedEvent` schema, and `AlertService` in Phase 2, we're designing against **real event structures** — not guesswork.

---

## Phase 1: Atomic Red Team — Attack Simulation Lab

### 1.1 Prerequisites & Environment Validation

#### Why This Matters
Atomic Red Team requires PowerShell 5.1+ with specific execution policies. Running it on a machine with Sysmon already installed means every technique execution generates the exact telemetry Forensiq will eventually ingest.

#### Step 1: Verify PowerShell Version

```powershell
# Check your PowerShell version
# Atomic Red Team requires PowerShell 5.1 or later
# Windows 10/11 ships with 5.1 by default
$PSVersionTable.PSVersion
```

**Expected output**: `5.1.xxxxx.xxxx` or higher. If you're on PowerShell 7.x (pwsh), that works too, but the module installation path differs. I recommend using **Windows PowerShell 5.1** (the built-in one) for maximum compatibility with Atomic Red Team, since many atomics use Windows-specific cmdlets.

#### Step 2: Set Execution Policy

```powershell
# Check current execution policy
Get-ExecutionPolicy -List

# Set execution policy to allow running downloaded scripts
# Scope: CurrentUser avoids requiring admin for policy change
# RemoteSigned: scripts downloaded from internet must be signed,
#               but locally created scripts can run unsigned
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Verify the change took effect
Get-ExecutionPolicy -Scope CurrentUser
```

> [!IMPORTANT]
> **Why `RemoteSigned` instead of `Bypass`?**
> `Bypass` disables all security checks — bad practice even in a lab. `RemoteSigned` allows local script execution while still requiring signatures on downloaded scripts. Atomic Red Team's `install-atomicredteam.ps1` is signed, so `RemoteSigned` works perfectly.

#### Step 3: Verify Sysmon Is Running

```powershell
# Check if Sysmon service is running
Get-Service sysmon* | Format-Table Name, Status, StartType

# Verify Sysmon is logging events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Format-Table TimeCreated, Id, Message -AutoSize -Wrap
```

**If Sysmon is not installed**, stop here — it's a prerequisite from your lab setup. Sysmon is what generates the rich process creation (Event ID 1), network connection (Event ID 3), file creation (Event ID 11), and registry modification (Event ID 13) events that Forensiq will consume.

#### Step 4: Verify Splunk Forwarder Is Running

```powershell
# Check Splunk Universal Forwarder service
Get-Service SplunkForwarder | Format-Table Name, Status, StartType

# Verify it's forwarding to your Splunk instance
# Check the outputs.conf
Get-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf"
```

---

### 1.2 Install Invoke-AtomicRedTeam

#### Why This Framework?
Atomic Red Team by Red Canary is the industry standard for MITRE ATT&CK technique simulation. Each "atomic test" maps 1:1 to a MITRE technique ID. This gives us:
- Deterministic, repeatable attack simulations
- Known MITRE mappings for every test (ground truth for our MITRE Mapping Agent)
- Predictable telemetry patterns (ground truth for our Correlation Engine)
- Safe, reversible tests with built-in cleanup commands

#### Step 5: Install the PowerShell Module

```powershell
# Install the Invoke-AtomicRedTeam execution framework
# IEX downloads and executes the install script from GitHub
# -Force: overwrite if already installed
# This installs the PowerShell module that provides:
#   - Invoke-AtomicTest (execute techniques)
#   - Get-AtomicTechnique (list techniques)
#   - Start-AtomicGUI (optional web UI)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force
```

**What this does:**
1. Downloads the `install-atomicredteam.ps1` script
2. Installs the `Invoke-AtomicRedTeam` PowerShell module to your module path
3. `-getAtomics`: also downloads the full atomics library (the actual test definitions)
4. `-Force`: overwrites existing installation if present

#### Step 6: Verify Installation

```powershell
# Import the module into your session
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Verify commands are available
Get-Command -Module Invoke-AtomicRedTeam

# Expected output should include:
#   Invoke-AtomicTest
#   Get-AtomicTechnique
#   Get-Prerequisites
#   Invoke-AtomicRunner
```

#### Step 7: Verify Directory Structure

```powershell
# The atomics library is installed here
Get-ChildItem "C:\AtomicRedTeam" -Directory

# Expected structure:
# C:\AtomicRedTeam\
# ├── atomics\           ← Individual technique definitions (YAML + scripts)
# │   ├── T1003\         ← Credential Dumping
# │   ├── T1053\         ← Scheduled Task/Job
# │   ├── T1059\         ← Command and Scripting Interpreter
# │   ├── T1547\         ← Boot or Logon Autostart Execution
# │   └── ...            ← ~800+ technique folders
# └── invoke-atomicredteam\  ← The execution framework module

# Count available techniques
(Get-ChildItem "C:\AtomicRedTeam\atomics" -Directory | Where-Object { $_.Name -match '^T\d+' }).Count
```

#### Step 8: Update Atomics (Future Use)

```powershell
# Update to latest atomics definitions from GitHub
# Run this periodically to get new techniques and fixes
# This pulls the latest YAML definitions from the Red Canary repo
Invoke-Expression (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force
```

---

### 1.3 Technique Simulation Catalog

> [!IMPORTANT]
> **Safety principle**: Every test listed below is safe for a personal lab. They create artifacts (processes, files, registry keys, scheduled tasks) but do NOT destroy data, exfiltrate information, or compromise system stability. Every test has a cleanup command. Run cleanup after each test.

#### How to Read Each Technique Block

For each technique below, I provide:
1. **MITRE ID & Name** — the official ATT&CK classification
2. **Why it matters** — real-world attack relevance
3. **Atomic test command** — exact PowerShell to execute
4. **Cleanup command** — reverses the test's effects
5. **Expected Sysmon events** — what telemetry Sysmon generates
6. **Expected Splunk search** — SPL to find the evidence
7. **MITRE mapping** — tactic → technique hierarchy

---

#### Technique 1: T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic**: Execution
**Why**: PowerShell is the #1 attack vector on Windows. Nearly every APT and commodity malware uses PowerShell for execution, download, and lateral movement. This is the most critical detection for any SOC.

```powershell
# List available tests for this technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Execute Test #1: Mimikatz-style PowerShell command
# This runs a benign PowerShell command that LOOKS like malicious activity
# (uses encoded commands, download cradles, etc.)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Cleanup: remove any artifacts created
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: powershell.exe`, `CommandLine: encoded/obfuscated command`, `ParentImage: powershell.exe` |
| 7 | Image Loaded | DLLs loaded by PowerShell (amsi.dll, clr.dll) |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\powershell.exe"
| table _time host user Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Execution (TA0002)
- **Technique**: Command and Scripting Interpreter (T1059)
- **Sub-technique**: PowerShell (T1059.001)

---

#### Technique 2: T1059.003 — Command and Scripting Interpreter: Windows Command Shell

**Tactic**: Execution
**Why**: cmd.exe is used alongside PowerShell for executing native Windows commands, batch scripts, and LOLBins (Living Off the Land Binaries). Attackers chain cmd.exe with tools like `certutil`, `bitsadmin`, and `wmic`.

```powershell
# List tests
Invoke-AtomicTest T1059.003 -ShowDetailsBrief

# Execute: Simulates cmd.exe being used for command execution
Invoke-AtomicTest T1059.003 -TestNumbers 1

# Cleanup
Invoke-AtomicTest T1059.003 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: cmd.exe`, `CommandLine: /c <commands>`, `ParentImage: powershell.exe` |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\cmd.exe"
| table _time host user Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Execution (TA0002)
- **Technique**: Command and Scripting Interpreter (T1059)
- **Sub-technique**: Windows Command Shell (T1059.003)

---

#### Technique 3: T1053.005 — Scheduled Task/Job: Scheduled Task

**Tactic**: Execution, Persistence, Privilege Escalation
**Why**: Scheduled tasks are one of the most common persistence mechanisms. APTs like APT29 and FIN7 use `schtasks.exe` to maintain access after reboot. This is also used for privilege escalation (running tasks as SYSTEM).

```powershell
# List tests
Invoke-AtomicTest T1053.005 -ShowDetailsBrief

# Execute: Creates a scheduled task (harmless — runs calc.exe or similar)
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Cleanup: Removes the scheduled task
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: schtasks.exe`, `CommandLine: /create /tn ...` |
| 11 | File Created | Task XML file in `C:\Windows\System32\Tasks\` |

**Expected Windows Event:**

| Event ID | Log | Description |
|----------|-----|-------------|
| 4698 | Security | A scheduled task was created |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\schtasks.exe" CommandLine="*/create*"
| table _time host user Image CommandLine ParentImage
| sort - _time
```

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4698
| table _time host TaskName Command
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004)
- **Technique**: Scheduled Task/Job (T1053)
- **Sub-technique**: Scheduled Task (T1053.005)

---

#### Technique 4: T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Tactic**: Persistence
**Why**: Registry Run Keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) are the classic persistence mechanism. Malware writes itself to these keys so it executes every time the user logs in. This is the first thing an analyst checks during triage.

```powershell
# List tests
Invoke-AtomicTest T1547.001 -ShowDetailsBrief

# Execute: Adds a registry Run key (harmless value)
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Cleanup: Removes the registry key
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: reg.exe`, `CommandLine: ADD HKCU\...\Run ...` |
| 13 | Registry Value Set | `TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\...`, `Details: <path to executable>` |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
  TargetObject="*\\CurrentVersion\\Run*"
| table _time host user EventCode TargetObject Details
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Persistence (TA0003)
- **Technique**: Boot or Logon Autostart Execution (T1547)
- **Sub-technique**: Registry Run Keys / Startup Folder (T1547.001)

---

#### Technique 5: T1543.003 — Create or Modify System Process: Windows Service

**Tactic**: Persistence, Privilege Escalation
**Why**: Creating malicious Windows services is an advanced persistence technique that survives reboots and runs as SYSTEM. APTs use `sc.exe` to install backdoor services.

```powershell
# List tests
Invoke-AtomicTest T1543.003 -ShowDetailsBrief

# Execute: Creates a Windows service (harmless — points to a benign executable)
# Requires admin privileges
Invoke-AtomicTest T1543.003 -TestNumbers 1

# Cleanup: Removes the service
Invoke-AtomicTest T1543.003 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: sc.exe`, `CommandLine: create ...` |
| 13 | Registry Value Set | `TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\...` |

**Expected Windows Event:**

| Event ID | Log | Description |
|----------|-----|-------------|
| 7045 | System | A new service was installed |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\sc.exe" CommandLine="*create*"
| table _time host user CommandLine ParentImage
| sort - _time
```

```spl
index=* sourcetype="WinEventLog:System" EventCode=7045
| table _time host ServiceName ImagePath ServiceType StartType AccountName
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Persistence (TA0003), Privilege Escalation (TA0004)
- **Technique**: Create or Modify System Process (T1543)
- **Sub-technique**: Windows Service (T1543.003)

---

#### Technique 6: T1003.001 — OS Credential Dumping: LSASS Memory

**Tactic**: Credential Access
**Why**: LSASS (Local Security Authority Subsystem Service) credential dumping is the hallmark of tools like Mimikatz. Detecting LSASS access is critical for identifying credential theft. Atomic Red Team simulates this safely using process access patterns.

```powershell
# List tests
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Execute: Simulates LSASS access (safe — uses Windows API calls, does NOT extract real credentials)
# Use test #6 which uses comsvcs.dll (a common LOLBin technique)
# Requires admin privileges
Invoke-AtomicTest T1003.001 -TestNumbers 6

# Cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 6 -Cleanup
```

> [!WARNING]
> Some credential dumping tests write a dump file. Always run cleanup. Test #6 (comsvcs.dll minidump) is commonly used because it mimics a real-world LOLBin technique without needing Mimikatz binaries.

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: rundll32.exe`, `CommandLine: comsvcs.dll, MiniDump ...` |
| 10 | Process Access | `TargetImage: lsass.exe`, `GrantedAccess: 0x1FFFFF` |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
  TargetImage="*\\lsass.exe"
| table _time host SourceImage TargetImage GrantedAccess CallTrace
| sort - _time
```

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  CommandLine="*comsvcs*MiniDump*"
| table _time host user Image CommandLine ParentImage
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Credential Access (TA0006)
- **Technique**: OS Credential Dumping (T1003)
- **Sub-technique**: LSASS Memory (T1003.001)

---

#### Technique 7: T1018 — Remote System Discovery

**Tactic**: Discovery
**Why**: After initial access, attackers enumerate the network to find lateral movement targets. Commands like `net view`, `nltest`, `arp -a`, and `ping` are classic discovery indicators.

```powershell
# List tests
Invoke-AtomicTest T1018 -ShowDetailsBrief

# Execute: Runs network discovery commands (net view, arp, nltest, etc.)
Invoke-AtomicTest T1018 -TestNumbers 1

# Cleanup (usually not needed — discovery commands don't create persistent artifacts)
Invoke-AtomicTest T1018 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: net.exe`, `CommandLine: view /domain` |
| 1 | Process Create | `Image: nltest.exe`, `CommandLine: /dclist:...` |
| 3 | Network Connect | Outbound connections from discovery tools |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\net.exe" OR Image="*\\nltest.exe" OR Image="*\\arp.exe" OR Image="*\\nbtstat.exe")
| table _time host user Image CommandLine ParentImage
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Discovery (TA0007)
- **Technique**: Remote System Discovery (T1018)

---

#### Technique 8: T1082 — System Information Discovery

**Tactic**: Discovery
**Why**: Attackers gather OS version, architecture, hostname, domain membership, and installed software to tailor subsequent attack stages. Commands like `systeminfo`, `hostname`, `whoami` are indicators.

```powershell
# List tests
Invoke-AtomicTest T1082 -ShowDetailsBrief

# Execute: Runs system information gathering commands
Invoke-AtomicTest T1082 -TestNumbers 1

# Cleanup
Invoke-AtomicTest T1082 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: systeminfo.exe` |
| 1 | Process Create | `Image: hostname.exe` |
| 1 | Process Create | `Image: whoami.exe` |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\systeminfo.exe" OR Image="*\\hostname.exe" OR Image="*\\whoami.exe")
| table _time host user Image CommandLine ParentImage
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Discovery (TA0007)
- **Technique**: System Information Discovery (T1082)

---

#### Technique 9: T1112 — Modify Registry

**Tactic**: Defense Evasion
**Why**: Attackers modify registry keys to disable security tools, hide malware configuration, or alter system behavior. Detecting unauthorized registry modifications is critical.

```powershell
# List tests
Invoke-AtomicTest T1112 -ShowDetailsBrief

# Execute: Modifies a registry value (harmless — creates/modifies a test key)
Invoke-AtomicTest T1112 -TestNumbers 1

# Cleanup: Restores original registry state
Invoke-AtomicTest T1112 -TestNumbers 1 -Cleanup
```

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: reg.exe`, `CommandLine: add ...` |
| 13 | Registry Value Set | `TargetObject`, `Details` |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| table _time host user EventCode TargetObject Details Image
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Defense Evasion (TA0005)
- **Technique**: Modify Registry (T1112)

---

#### Technique 10: T1021.006 — Remote Services: Windows Remote Management (WinRM)

**Tactic**: Lateral Movement
**Why**: WinRM / PowerShell Remoting is a legitimate admin tool that attackers abuse for lateral movement. Detecting `Enter-PSSession`, `Invoke-Command`, and `winrs.exe` is essential.

```powershell
# List tests
Invoke-AtomicTest T1021.006 -ShowDetailsBrief

# Execute: Simulates WinRM usage (connects to localhost — safe in lab)
Invoke-AtomicTest T1021.006 -TestNumbers 1

# Cleanup
Invoke-AtomicTest T1021.006 -TestNumbers 1 -Cleanup
```

> [!NOTE]
> This test may require WinRM to be enabled on your host. If it fails, run `Enable-PSRemoting -Force` as admin first. In a real environment, WinRM is typically already enabled on domain-joined machines.

**Expected Sysmon Events:**

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | `Image: wsmprovhost.exe` (WinRM host process) |
| 3 | Network Connect | Connection on port 5985 (HTTP) or 5986 (HTTPS) |

**Splunk Search:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  (EventCode=1 Image="*\\wsmprovhost.exe") OR
  (EventCode=3 DestinationPort=5985)
| table _time host user EventCode Image CommandLine DestinationIp DestinationPort
| sort - _time
```

**MITRE Mapping:**
- **Tactic**: Lateral Movement (TA0008)
- **Technique**: Remote Services (T1021)
- **Sub-technique**: Windows Remote Management (T1021.006)

---

### 1.4 Recommended Execution Order

> [!TIP]
> Execute techniques in this order. It mirrors a realistic attack chain (kill chain), which gives our Correlation Engine and Timeline Agent real sequential data to work with.

| Step | Technique | Tactic | Kill Chain Phase |
|------|-----------|--------|------------------|
| 1 | T1059.001 | Execution | Initial Foothold |
| 2 | T1059.003 | Execution | Command Execution |
| 3 | T1082 | Discovery | Reconnaissance |
| 4 | T1018 | Discovery | Network Mapping |
| 5 | T1547.001 | Persistence | Establishing Persistence |
| 6 | T1053.005 | Persistence | Backup Persistence |
| 7 | T1543.003 | Persistence | Service Persistence |
| 8 | T1112 | Defense Evasion | Covering Tracks |
| 9 | T1003.001 | Credential Access | Credential Theft |
| 10 | T1021.006 | Lateral Movement | Spreading |

**Run them with ~30-60 second gaps** between each technique. This creates a realistic timeline with distinct timestamps for our Timeline Agent to reconstruct.

### 1.5 Comprehensive Verification

After running all techniques, verify the full telemetry chain:

#### Verify Sysmon Captured Events

```powershell
# Count Sysmon events in the last hour
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) } |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Name, Count
```

#### Verify Events in Splunk

```spl
# Master search: all Sysmon process creation events in the last hour
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  earliest=-1h
| stats count by Image
| sort - count
```

```spl
# Registry modifications
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
  earliest=-1h
| stats count by TargetObject
| sort - count
```

```spl
# Network connections
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  earliest=-1h
| stats count by Image DestinationIp DestinationPort
| sort - count
```

```spl
# Full attack timeline
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  (EventCode=1 OR EventCode=3 OR EventCode=10 OR EventCode=11 OR EventCode=13)
  earliest=-1h
| table _time EventCode Image CommandLine ParentImage TargetObject DestinationIp
| sort _time
```

### 1.6 Cleanup Everything

```powershell
# Run cleanup for ALL techniques in one sweep
$techniques = @("T1059.001", "T1059.003", "T1053.005", "T1547.001",
                "T1543.003", "T1003.001", "T1018", "T1082", "T1112", "T1021.006")

foreach ($t in $techniques) {
    Write-Host "Cleaning up $t..." -ForegroundColor Yellow
    try {
        Invoke-AtomicTest $t -TestNumbers 1 -Cleanup -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Cleanup for $t skipped (no artifacts)" -ForegroundColor Gray
    }
}

Write-Host "All cleanups complete." -ForegroundColor Green
```

---

### 1.7 MITRE ATT&CK Coverage Map

This is the coverage our simulation gives us — and what Forensiq's MITRE Mapping Agent will need to detect:

```
MITRE ATT&CK Navigator Coverage (Phase 1)

┌─────────────────────────────────────────────────────────────────┐
│ Tactic              │ Techniques Covered                       │
├─────────────────────┼──────────────────────────────────────────┤
│ Execution           │ T1059.001, T1059.003, T1053.005         │
│ Persistence         │ T1547.001, T1053.005, T1543.003         │
│ Privilege Escalation│ T1053.005, T1543.003                    │
│ Defense Evasion     │ T1112                                   │
│ Credential Access   │ T1003.001                               │
│ Discovery           │ T1018, T1082                            │
│ Lateral Movement    │ T1021.006                               │
└─────────────────────┴──────────────────────────────────────────┘

Tactics covered: 7 / 14
Techniques covered: 10
Sub-techniques covered: 7
```

---

## Phase 2: Backend Architecture (Overview)

> [!NOTE]
> Phase 2 detailed implementation plan will be created after you confirm Phase 1 is complete and you have telemetry flowing in Splunk. I'm including the architecture overview here so you understand *why* Phase 1 data shapes Phase 2 decisions.

### 2.1 Why Phase 1 Data Shapes Phase 2

After executing Phase 1, you'll have real Sysmon events in Splunk. When we build the backend:

- **`NormalizedEvent` schema** will be designed from the *actual* field names in your Sysmon data (not guesswork)
- **`SplunkClient.search()`** will be tested against *real* SPL queries that we've already validated
- **`AlertService`** will ingest *real* triggered alerts from the saved searches you'll create in Splunk
- **`MITREMappingService`** will be validated against *known* technique IDs from our simulation
- **`CorrelationEngine`** will be tested against *known* attack chains with predictable relationships

### 2.2 Architecture Decisions (Preview)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Package manager | `uv` | 10-100x faster than pip, lockfile support, Python 3.13 compatible |
| Async framework | FastAPI + `httpx` | Non-blocking Splunk API calls, high concurrency |
| ORM | SQLAlchemy 2.0 async | Native async session, type-safe queries |
| Migrations | Alembic | SQLAlchemy-native, auto-generation |
| Task queue | Celery + Redis | Production-proven, multiple queue support for agent isolation |
| SIEM abstraction | Provider interface | `SIEMProvider` protocol class → `SplunkProvider` implementation |
| Auth | JWT (access + refresh) | Stateless, horizontally scalable |
| Config | Pydantic `BaseSettings` | Type-safe, .env loading, validation at startup |
| Logging | `structlog` | JSON structured logging, async-safe, production-grade |
| Testing | `pytest` + `pytest-asyncio` + `httpx` | Async test support, `TestClient` for API tests |

### 2.3 SIEM Abstraction Layer (Key Architecture Decision)

This is the most important architectural decision in Forensiq. Instead of coupling directly to Splunk:

```
┌─────────────────────────────────────────────┐
│              Forensiq Services              │
│  (SearchService, AlertService, etc.)        │
├─────────────────────────────────────────────┤
│           SIEMProvider Protocol             │
│  authenticate()                             │
│  search(query, time_range) → NormalizedEvent│
│  get_alerts() → Alert                       │
│  list_indexes() → list[str]                 │
├─────────┬───────────┬──────────┬────────────┤
│ Splunk  │ Elastic   │ Sentinel │ QRadar     │
│Provider │Provider   │Provider  │Provider    │
│(Phase 2)│(Future)   │(Future)  │(Future)    │
└─────────┴───────────┴──────────┴────────────┘
```

Every SIEM integration implements the same `SIEMProvider` protocol. Services never know which SIEM they're talking to. This is how we achieve SIEM-agnosticism without changing AI agents.

---

## Open Questions

> [!IMPORTANT]
> Before proceeding, I need your input on these decisions:

1. **Splunk version**: What version of Splunk Enterprise are you running? This affects REST API endpoints and Dashboard Studio JSON format.

2. **Sysmon config**: Which Sysmon configuration are you using? (SwiftOnSecurity? Olaf Hartong? Custom?) This determines which Event IDs are enabled and affects our Splunk searches.

3. **Splunk indexes**: What index name are your Windows/Sysmon events going into? (`main`? `wineventlog`? custom?) This affects every SPL query.

4. **Admin access**: Do you have admin privileges on the Windows host? Some techniques (T1543.003 Service, T1003.001 LSASS) require elevation.

5. **Phase 1 scope**: Do you want to proceed with Phase 1 (Atomic Red Team) now, or would you prefer to jump directly to Phase 2 (Backend) if you already have telemetry flowing?

---

## Verification Plan

### Phase 1 Verification
- [ ] PowerShell 5.1+ confirmed
- [ ] Execution policy set to `RemoteSigned`
- [ ] Sysmon service running
- [ ] Splunk Forwarder running and forwarding
- [ ] Invoke-AtomicRedTeam installed
- [ ] Atomics library downloaded
- [ ] All 10 techniques executed successfully
- [ ] Sysmon events visible in Event Viewer
- [ ] Events visible in Splunk via SPL queries
- [ ] All cleanups run successfully

### Phase 2 Prerequisites (after Phase 1)
- [ ] At least 100 Sysmon events indexed in Splunk
- [ ] At least 3 different Event IDs captured (1, 3, 13)
- [ ] Splunk REST API accessible from development machine
- [ ] Docker and Docker Compose installed
- [ ] Python 3.13 installed
- [ ] PostgreSQL accessible (or ready for Docker)
