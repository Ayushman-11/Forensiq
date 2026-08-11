# Forensiq — Development Plan

> Intelligent Security Operations & Investigation Platform

---

## Phase 0: Project Scaffolding (Week 1)

### 0.1 Repository & Structure
- Initialize Git repo on GitHub
- Monorepo structure:
  ```
  forensiq/
  ├── backend/            # FastAPI application
  │   ├── api/            # REST endpoints
  │   ├── core/           # Config, security, JWT
  │   ├── db/             # Models, migrations, pgvector
  │   └── services/       # Business logic layer
  ├── agents/             # AI agent services
  │   ├── context_agent/      # Alert Context Agent
  │   ├── enrichment_agent/   # IOC Enrichment Agent
  │   ├── correlation_agent/  # Correlation Agent
  │   ├── mitre_agent/        # MITRE Mapping Agent
  │   ├── timeline_agent/     # Timeline Agent
  │   ├── risk_agent/         # Risk Assessment Agent (LLM)
  │   └── recommendation_agent/ # Investigation Recommendation Agent (LLM)
  ├── frontend/           # Next.js application
  │   ├── app/            # App Router pages
  │   ├── components/     # React components
  │   └── lib/            # API client, utils
  ├── worker/             # Celery task definitions
  ├── docker/             # Dockerfiles and compose configs
  ├── docs/               # Documentation
  └── scripts/            # Dev scripts, seed data
  ```

### 0.2 Development Environment
- Docker Compose dev environment:
  - `postgres` (with pgvector extension)
  - `redis` (message broker)
  - `backend` (FastAPI hot-reload)
  - `frontend` (Next.js dev server)
  - `celery-worker` (task worker)
- `.env` template with all required API keys
- Pre-commit hooks (lint, format, type-check)

### 0.3 Database
- PostgreSQL 15+ with pgvector extension
- Core tables:
  - `users` — id, email, password_hash, role, org_id
  - `organizations` — id, name, slug, settings
  - `alerts` — id, org_id, splunk_alert_id, status, raw_payload, created_at
  - `investigations` — id, alert_id, status, analyst_id, created_at
  - `iocs` — id, investigation_id, type (ip/domain/url/hash), value
  - `enrichments` — id, ioc_id, source, reputation, threat_score, raw_response
  - `correlations` — id, investigation_id, correlated_alert_id, match_type, match_value
  - `mitre_mappings` — id, investigation_id, tactic, technique, description
  - `timeline_events` — id, investigation_id, timestamp, event_type, description, source
  - `risk_assessments` — id, investigation_id, risk_score, confidence_score, priority
  - `recommendations` — id, investigation_id, summary, evidence_summary, next_steps
  - `analyst_notes` — id, investigation_id, analyst_id, content, created_at
  - `reports` — id, investigation_id, type, format, generated_at
- pgvector columns for semantic search on alerts and investigations

---

## Phase 1: Core Backend (Week 1–2)

### 1.1 Authentication & Authorization
- JWT access + refresh token flow
- RBAC middleware: Admin, SOC Manager, SOC Analyst
- Organization-scoped data access (multi-tenant isolation)
- Login, logout, token refresh endpoints

### 1.2 FastAPI Backend Skeleton
- App factory pattern with structured routers
- Dependency injection for DB session and current user
- Request validation via Pydantic models
- Structured response schemas for every endpoint
- Error handling middleware
- API versioning (`/api/v1/...`)
- OpenAPI docs auto-generated

### 1.3 Celery + Redis Setup
- Celery app factory
- Redis as broker and result backend
- Task base class with retry logic and error logging
- Task routing by queue (agents get dedicated queues)
- Health check endpoint for worker status

---

## Phase 2: Splunk Integration & Alert Management (Week 2–3)

### 2.1 Splunk API Client
- Splunk REST API wrapper (`/services/search/jobs`)
- Search job creation with SPL queries
- Poll search job status, retrieve results
- Alert fetch service (poll Splunk for triggered alerts)
- Event query service (fetch raw events for correlation)
- Connection pool and rate limiting
- Credential management per organization

### 2.2 Alert Ingestion
- Splunk webhook receiver / polling service
- Alert deduplication logic
- Alert normalization layer (Splunk raw → Forensiq canonical format)
- IOC extraction from alert payload (regex patterns for IP, domain, URL, hash)
- Alert queue with priority based on severity

### 2.3 Alert Management API
- `GET /alerts` — paginated, filterable, searchable alert list
- `GET /alerts/{id}` — full alert detail
- `PATCH /alerts/{id}/status` — status transitions
- `POST /alerts/{id}/investigate` — trigger investigation pipeline
- Alert search with full-text and field-level filters

---

## Phase 3: AI Agent Pipeline (Week 3–5)

### 3.1 Orchestration Framework
- LangGraph state graph definition
- State schema: `InvestigationState` (typed dict carrying alert context, IOCs, enrichments, correlations, MITRE mapping, timeline, risk, recommendation)
- Sequential agent execution with state passing
- Each agent reads from state, appends its output, passes to next
- Error handling: agent failure → skip downstream, log error, notify
- Investigation status tracking through pipeline

### 3.2 Alert Context Agent
Python service agent — no LLM.

**Input**: Alert ID, raw Splunk payload
**Logic**:
- Parse alert fields (hostname, username, process name, PID, command line)
- Lookup asset info from Splunk (CMDB enrichment if available)
- Extract detection rule name and metadata
- Gather file paths, network connections from alert
**Output**: Structured `AlertContext` object

### 3.3 IOC Enrichment Agent
Python service agent — API orchestration.

**Input**: Extracted IOC list (IP, domain, URL, file hash)
**Integrations**:
- VirusTotal → file hash, URL reputation, malware detection ratio
- AbuseIPDB → IP abuse confidence, reports, last reported
- AlienVault OTX → pulses, related IOCs, campaign associations
**Logic**:
- Parallel API calls per IOC type
- Response normalization into unified enrichment schema
- Cache enrichments in DB to avoid repeat API calls
**Output**: List of `Enrichment` objects per IOC

### 3.4 Correlation Agent
Python service agent — Splunk event search.

**Input**: Alert IOCs, hostname, username, process name, file hash
**Logic**:
- For each correlation key (IP, user, host, process, hash), query Splunk for historical events in configurable time window
- Cross-reference with past alerts in Forensiq DB
- Rank correlations by recency and relevance
**Output**: List of `Correlation` objects with matched events

### 3.5 MITRE Mapping Agent
Python service agent — STIX dataset lookup + heuristic mapping.

**Input**: Detection rule name, alert description, process info, correlated events
**Logic**:
- Load MITRE ATT&CK STIX dataset (bundled JSON or periodic sync)
- Keyword + heuristic matching: detection rule → technique
- Process creation events → Execution techniques
- Network connections → C2 / Lateral Movement techniques
- Optional: LLM-assisted mapping for low-confidence matches
**Output**: List of `MITREMapping` objects (tactic, technique ID, technique name, description)

### 3.6 Timeline Agent
Python service agent — chronological assembly.

**Input**: Alert event, correlated events, IOC enrichment timestamps
**Logic**:
- Sort all events by timestamp
- Deduplicate identical events
- Group into phases (Initial Access → Execution → Persistence → C2 → Impact)
- Generate human-readable event descriptions
**Output**: Ordered list of `TimelineEvent` objects

### 3.7 Risk Assessment Agent
**LLM Agent** — LangChain + GPT-4.1/5.

**Input**: Full investigation state (alert context, enrichments, correlations, MITRE mappings, timeline)
**LLM Prompt**:
- Analyze severity of IOCs (known malware? high abuse score?)
- Assess MITRE technique criticality and attack phase
- Evaluate breadth of correlation (how many assets affected?)
- Calculate risk score 0–100
- Calculate confidence score 0–100 (how certain is the assessment?)
- Assign priority: low / medium / high / critical
**Structured Output**: `RiskAssessment` object

### 3.8 Investigation Recommendation Agent
**LLM Agent** — LangChain + GPT-4.1/5 / Qwen 3.

**Input**: Full investigation state including risk assessment
**LLM Prompt**:
- Synthesize investigation findings into narrative summary
- Summarize key evidence collected
- Based on MITRE mapping and correlations, suggest concrete next investigation steps
- Format as actionable checklist
**Structured Output**: `Recommendation` object

### 3.9 Pipeline Execution
- Triggered by `POST /alerts/{id}/investigate`
- Celery chain task: `context → enrich → correlate → mitre → timeline → risk → recommend`
- Each task updates `investigations` table status
- Frontend polls `/investigations/{id}/status` for progress
- On completion, full investigation state persisted in DB

---

## Phase 4: Investigation Dashboard (Week 5–6)

### 4.1 Dashboard Layout
- Split-panel layout: alert summary on left, investigation results on right
- Real-time pipeline progress indicator
- Sections collapse/expand for dense data

### 4.2 Dashboard Components
| Component | Content |
|---|---|
| **Alert Summary** | Alert name, severity, timestamp, source, status badge |
| **Risk Gauge** | Risk score (0–100) as gauge chart, confidence bar, priority tag |
| **Timeline View** | Vertical chronological timeline with event cards, phase grouping |
| **IOC Table** | IOC value, type, reputation, threat score, source links |
| **MITRE Mapping** | Tactic → Technique cards with descriptions, link to ATT&CK |
| **Correlated Events** | Table of related alerts/events with match type and timestamp |
| **Evidence Panel** | Aggregated evidence from all agents |
| **Analyst Notes** | Markdown editor, auto-saved, per-investigation |

### 4.3 Interactions
- Filter timeline by phase or event type
- Click IOC to see raw enrichment data
- Click MITRE technique to view full ATT&CK detail
- Toggle correlation time window
- Export/share investigation

---

## Phase 5: Reporting (Week 6–7)

### 5.1 Report Generator
- Template-based report generation
- Sections: Executive Summary, Alert Overview, Timeline, IOCs & Enrichment, MITRE Mapping, Evidence, Recommendations
- Output formats: PDF (primary), Markdown, HTML
- Server-side rendering with WeasyPrint or similar

### 5.2 Report Templates
- **Investigation Report** — full detail for SOC Manager review
- **Executive Summary** — one-page summary for leadership
- **Evidence Bundle** — raw evidence collection for audit

### 5.3 Report API
- `POST /investigations/{id}/report` — generate report
- `GET /reports/{id}/download` — download generated file
- `GET /investigations/{id}/reports` — list prior reports

---

## Phase 6: Multi-Tenancy & SaaS Readiness (Week 7–8)

### 6.1 Tenant Isolation
- Organization-level data scoping (every query filtered by `org_id`)
- Per-organization Splunk connection config
- Per-organization API key storage for threat intel services
- Rate limiting per tenant

### 6.2 Organization Management
- Admin CRUD for organizations
- User invitation flow (email invite → accept → role assignment)
- Organization settings page (Splunk config, API keys, retention policy)

---

## Phase 7: Testing, Deployment & Documentation (Week 8–9)

### 7.1 Testing
- Unit tests for all agents (pytest, pytest-asyncio)
- Integration tests for agent pipeline end-to-end
- API contract tests for FastAPI endpoints
- Frontend component tests (React Testing Library)
- LLM agent output validation (schema conformance, score range checks)

### 7.2 Production Deployment
- Docker Compose production stack with resource limits
- Nginx reverse proxy for frontend + backend
- PostgreSQL with volume persistence and backup
- Redis persistence configuration
- Environment variable management for secrets
- Health check endpoints for all services

### 7.3 Documentation
- API documentation (OpenAPI/Swagger auto-generated + manual annotations)
- Architecture decision records (ADRs)
- Agent design docs (one per agent)
- Deployment guide
- User guide for SOC analysts
- Research paper

---

## Deliverable Summary

| # | Deliverable | Phase | Priority |
|---|---|---|---|
| 1 | SaaS Web Dashboard | Phase 4, 6 | P0 |
| 2 | Splunk Integration | Phase 2 | P0 |
| 3 | AI Agent Pipeline | Phase 3 | P0 |
| 4 | Alert Investigation Workspace | Phase 4 | P0 |
| 5 | Threat Intelligence Module | Phase 3 (IOC Agent) | P0 |
| 6 | MITRE ATT&CK Mapping | Phase 3 (MITRE Agent) | P1 |
| 7 | Risk Assessment Engine | Phase 3 (Risk Agent) | P1 |
| 8 | Investigation Timeline | Phase 3 (Timeline Agent) | P1 |
| 9 | Investigation Report Generator | Phase 5 | P1 |
| 10 | Dockerized Deployment | Phase 0, 7 | P0 |
| 11 | Research Paper | Phase 7 | P2 |
| 12 | Project Documentation | Phase 7 | P1 |

---

## Key Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Splunk API rate limits / slow queries | Pipeline delay | Caching layer, async polling, configurable time windows |
| LLM API cost at scale | Budget overrun | Cache LLM outputs for similar alerts, use smaller models for low-severity, batch processing |
| Threat intel API rate limits | Incomplete enrichment | Staggered API keys, response caching, graceful degradation if source unavailable |
| pgvector performance at scale | Slow semantic queries | Index tuning, consider dedicated vector DB (Qdrant/Milvus) if needed |
| Multi-agent pipeline failures | Partial investigations | Per-agent error isolation, retry with backoff, partial results still displayed |

---

## Tech Debt Awareness
- pgvector may need replacement by dedicated vector DB at scale — abstract the interface early
- LLM agent prompts will need iterative tuning — build a prompt registry with versioning
- MITRE STIX dataset needs periodic sync — automate via cron/celery beat
- Splunk API client should be protocol-abstracted to eventually support other SIEMs (Elastic, Sentinel) in future phases beyond current scope