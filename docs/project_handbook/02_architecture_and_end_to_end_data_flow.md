# Chapter 2: Architecture & End-to-End Data Flow

This chapter explains the exact path that information takes from the moment an attacker performs an action on a computer to the moment an analyst views the completed investigation and downloads a PDF.

---

## 1. What Technologies Power Forensiq?

Forensiq is built using modern, production-grade enterprise software technologies:

| Layer | Technology | Why We Use It |
|---|---|---|
| **Backend Framework** | **FastAPI (Python 3.11+)** | High performance, native asynchronous (`async`/`await`) request handling, automatic OpenAPI/Swagger documentation, and strong Pydantic typing. |
| **Agent Orchestration** | **LangGraph & LangChain** | State-machine based multi-agent pipeline with deterministic node execution, state checkpointing, and conditional routing. |
| **Artificial Intelligence** | **Google Gemini / OpenAI LLM** | Synthesizes complex context, generates human-readable incident summaries, and devises tailored SOC remediation playbooks. |
| **Primary Database** | **MongoDB (via Motor)** | High-throughput document store ideal for heterogeneous security events, polymorphic alert schemas, and thread caches. |
| **Frontend Framework** | **Next.js 14+ (App Router)** | Modern React framework with TypeScript, server-side rendering, fast hydration, and clean modular pages. |
| **Styling & Design System** | **Tailwind CSS + CSS Custom Properties** | Bespoke Vercel/Linear-inspired minimalist theme tokens supporting seamless switching between true Black mode (`#000000`) and crisp White mode (`#FFFFFF`). |
| **Live Communication** | **WebSockets (`/ws`) + Server-Sent Events (SSE)** | Delivers bidirectional, live sub-second streaming logs of agent decisions directly into the analyst's browser. |
| **Document Generation** | **ReportLab Engine** | Compiles clean, branded binary PDF reports directly on the server without relying on fragile browser print dialogs. |
| **SIEM Integration** | **Splunk Enterprise REST API** | Connects to enterprise log stores with automated search job dispatching and paginated result streaming. |

---

## 2. End-to-End Data Journey: From Raw Log to Investigation Report

Here is the step-by-step path that every security event travels through:

```
[Attacker Action on Host]
         │
         ▼
[1. Splunk Log Engine]  ──────────► Stores raw Windows/Sysmon log in index (e.g., 'attack_data')
         │
         ▼ (Polled every 30s via REST API: /services/search/jobs)
[2. Poller & SPL Guard] ──────────► Executes read-only search queries; acquires distributed lease lock
         │
         ▼
[3. Normalization Engine] ────────► Filters benign noise, groups duplicate alerts, standardizes fields
         │
         ▼
[4. Detection Engine]   ──────────► Evaluates 8 detection rules; matches malicious activity
         │
         ▼
[5. MongoDB Database]   ──────────► Saves normalized alert document with status "New"
         │
         ▼ (Analyst clicks "Run Agent Pipeline" or auto-triggered)
[6. LangGraph Multi-Agent] ───────► Launches 7-Node Autonomous Investigation (Context, Threat Intel, Risk, etc.)
         │
         ├───► Streams step-by-step progress via WebSockets to Next.js UI
         │
         ▼
[7. MongoDB Database]   ──────────► Updates alert with status "Investigated", Risk Score, and Playbook
         │
         ▼
[8. ReportLab PDF Engine] ────────► Generates binary Executive (1-page) or Full Technical PDF report
```

---

## 3. Detailed Component Breakdown

### Component A: Ingestion Layer (`backend/app/infrastructure/siem/` & `services/poller.py`)
- **What it does**: Constantly connects to the SIEM (Splunk) to check if any new security logs have arrived.
- **Key Safety Mechanisms**:
  - **Distributed Lease Locking (`app/services/lease.py`)**: If multiple backend server instances are running at the same time, only **one** instance will query Splunk at any given moment. This prevents duplicate alert creation and database race conditions.
  - **SPL Guardrails (`app/services/spl_guard.py`)**: SPL stands for *Search Processing Language* (Splunk's query language). The guardrail inspects every query and blocks dangerous or destructive commands like `delete`, `outputcsv`, or `drop`.

### Component B: Normalization & Noise Reduction (`backend/app/normalization/`)
- **The Problem**: A firewall might generate 50,000 logs in 5 minutes for the exact same connection attempts. If an analyst saw 50,000 separate alerts, the system would be unusable.
- **The Solution**: 
  1. **Canonical Event Mapping (`canonical.py`)**: Standardizes different log types into a single clean Python object containing standard attributes (`host`, `user`, `process_name`, `command_line`, `source_ip`, `dest_ip`, `hashes`).
  2. **Noise Filtering (`noise.py`)**: Checks incoming events against lists of known harmless background noise (e.g., Windows Update, internal health checks) and discards them before they clutter the system.
  3. **Event Grouping & Deduplication (`dedup.py`)**: Collapses identical events from the same host, user, and rule occurring within a time window into a single alert with a `count` property (e.g., "Observed 124 times").

### Component C: Multi-Agent AI Core (`backend/app/agents/`)
- Implemented as a stateful graph using **LangGraph**.
- Each of the 7 nodes has a dedicated, specialized responsibility. 
- The state object (`AgentState`) is passed from node to node, accumulating intelligence at every step.
- *(Covered in complete detail in Chapter 4)*.

### Component D: Frontend UI & Streaming (`frontend/src/`)
- Written in TypeScript and Next.js.
- Connects to the backend via REST endpoints (`/api/v1/alerts`, `/api/v1/metrics`, etc.) for data fetching.
- Opens persistent **WebSocket** connections (`ws://localhost:8001/api/v1/alerts/{id}/ws`) to receive real-time streaming progress as the AI agents execute their investigation steps.
- If WebSockets are blocked by corporate proxies or firewalls, the client automatically degrades seamlessly to **Server-Sent Events (SSE)**.

---

## 4. Directory Structure Map

Understanding where files live in the repository makes it easy to navigate and modify code:

```
Forensiq/
├── backend/                         # FastAPI Application Backend
│   ├── app/
│   │   ├── agents/                  # 7 LangGraph Autonomous Investigation Agents
│   │   │   ├── context_agent.py     # Extracts parameters, command lines & users
│   │   │   ├── enrichment_agent.py  # VirusTotal & AbuseIPDB Threat Intel
│   │   │   ├── correlation_agent.py # Cross-correlates matching alerts
│   │   │   ├── mitre_agent.py       # Maps TTPs to MITRE ATT&CK Matrix
│   │   │   ├── timeline_agent.py    # Builds chronological attack story
│   │   │   ├── risk_agent.py        # Calculates mathematical Risk Score (0-100)
│   │   │   ├── recommendation_agent.py # Generates AI Playbook & advice
│   │   │   └── pipeline.py          # Assembles the LangGraph State Graph
│   │   ├── api/v1/endpoints/        # REST & WebSocket API Endpoints
│   │   │   ├── alerts.py            # Alert queries, updates, MITRE stats & WebSocket stream
│   │   │   ├── reports.py           # Report generation & binary PDF downloads
│   │   │   ├── search.py            # Direct Splunk SPL search proxy
│   │   │   └── auth.py              # User authentication & JWT tokens
│   │   ├── infrastructure/          # External integrations (Splunk client, Threat Intel)
│   │   ├── models/                  # Pydantic & database schemas
│   │   ├── normalization/           # Canonical mapping, deduplication & noise reduction
│   │   └── services/                # Ingestion engine, ReportLab PDF, Splunk poller
│   └── tests/                       # Automated pytest test suites (329 passing tests)
│
├── frontend/                        # Next.js 14+ Frontend Application
│   └── src/
│       ├── app/                     # Next.js App Router Pages
│       │   ├── page.tsx             # Main SOC Dashboard (KPIs, Charts, MITRE Matrix)
│       │   ├── alerts/page.tsx      # Full Alerts Triage Queue
│       │   ├── investigations/page.tsx # Investigation Workspace & Process Tree DAG
│       │   ├── reports/page.tsx     # Report Center & PDF Download Hub
│       │   └── search/page.tsx      # Splunk SPL Query Console
│       ├── components/              # Modular UI Components
│       │   ├── mitre/MitreMatrix.tsx # Compact 10-Tactic Heatmap
│       │   ├── investigation/       # ProcessTreeGraph, InvestigationModal
│       │   └── enrichment/          # IocHoverCard (Defanging & Threat Intel popover)
│       └── lib/                     # API fetchers, defang utilities, TypeScript types
└── docs/                            # Comprehensive documentation & guides
```

---

*Next Chapter: [Chapter 3: SIEM Ingestion & Normalization Engine](file:///d:/Forensiq/docs/project_handbook/03_siem_ingestion_and_normalization.md)*
