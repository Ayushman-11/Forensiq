---
name: project-context
description: Comprehensive understanding of the Forensiq project including problem statement, solution approach, stakeholders, uniqueness, and innovation
metadata:
  type: project
---

# Forensiq Project Context

## Problem Statement
Forensiq is an AI-Agent Driven Security Operations & Investigation Platform designed to address the challenges faced by Security Operations Centers (SOCs) in investigating security alerts. The core problem is the overwhelming volume of alerts, manual investigation processes, and the need for rapid, evidence-based threat analysis.

## Solution Approach
Forensiq solves this by implementing a comprehensive AI-driven investigation pipeline that:
1. **Ingests alerts** from SIEM systems (initially Splunk) 
2. **Orchestrates multiple specialized AI agents** to perform different investigation tasks
3. **Provides a unified dashboard** for analysts to view investigation results
4. **Generates actionable recommendations** and automated reports

## Stakeholders
- **SOC Analysts**: Primary users who investigate alerts and use the platform for investigations
- **SOC Managers/Leaders**: Oversee investigations, review reports, and manage team performance
- **Security Engineers**: Configure and maintain the platform, integrate with existing security tools
- **Executive Leadership**: Receive high-level reports and metrics on security posture

## What Makes Forensiq Unique & Innovative

### 1. Multi-Agent AI Investigation Pipeline
Unlike traditional SIEM tools that focus on detection and alerting, Forensiq deploys a pipeline of specialized AI agents:
- **Context Agent**: Extracts and normalizes alert context from raw SIEM data
- **IOC Enrichment Agent**: Enriches Indicators of Compromise using threat intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX)
- **Correlation Agent**: Finds historical events and related alerts in the SIEM
- **MITRE Mapping Agent**: Maps attack behaviors to MITRE ATT&CK framework techniques
- **Timeline Agent**: Constructs chronological timelines of attack events
- **Risk Assessment Agent**: LLM-powered agent that calculates risk scores and confidence levels
- **Recommendation Agent**: LLM-powered agent that provides actionable investigation steps

### 2. SIEM-Agnostic Architecture
Forensiq implements a clean abstraction layer (`SIEMProvider` protocol) that allows switching between different SIEM platforms (Splunk, Elastic, Sentinel, QRadar) without changing the core investigation logic or AI agents.

### 3. Attack Simulation-Based Development
The project uniquely begins with Phase 1: Atomic Red Team attack simulation lab, ensuring that:
- Backend schemas are designed against real telemetry data, not guesswork
- Splunk queries are validated against actual attack patterns
- MITRE mappings have ground truth for validation
- Investigation timelines are based on real attack sequences

### 4. Comprehensive Investigation Workspace
The platform provides a single-pane-of-glass investigation view that includes:
- Alert summary with severity and status
- Risk gauge visualization with confidence metrics
- Interactive timeline view with phase grouping
- IOC tables with reputation scores and threat intelligence links
- MITRE tactic→technique mapping with ATT&CK links
- Correlated events table showing related alerts
- Evidence panel aggregating findings from all agents
- Analyst notes with markdown support

### 5. Automated Reporting & Evidence Generation
Forensiq automates the creation of:
- Executive summary reports for leadership
- Detailed investigation reports for SOC review
- Evidence bundles for audit and legal purposes
- Multiple export formats (PDF, HTML, Markdown)

### 6. Multi-Tenant SaaS Architecture
Built with enterprise scalability in mind:
- Organization-level data isolation
- Per-tenant configuration management
- Role-based access control (Admin, SOC Manager, SOC Analyst)
- API key management per tenant for threat intelligence services

## Technical Innovation Highlights

### LangGraph Orchestration
Uses LangGraph state graphs to manage the complex workflow of agent execution with proper error handling and state passing.

### pgvector for Semantic Search
Integrates PostgreSQL with pgvector extension for semantic search capabilities on alerts and investigations, enabling similarity-based threat hunting.

### Async-First Backend
Built with FastAPI and async SQLAlchemy 2.0 for high concurrency when dealing with external APIs (SIEM, threat intel services).

### Dockerized Deployment
Provides both development and production Docker Compose configurations for easy deployment and scaling.

## Current Implementation Status
Based on the project status report:
- � ✅ Phase 0 (Project Scaffolding) completed
- � ✅ Phase 1 (Core Backend) partially implemented:
  - Application core with structured logging
  - Versioned API router (/api/v1/)
  - Health checks, alerts management, and search endpoints
  - SIEM abstraction layer with Splunk implementation
  - NormalizedEvent schema
  - Basic test suite
- � ✅ Frontend initialized with:
  - SOC Overview dashboard with KPI charts
  - Recent alerts data table
  - Dedicated alerts investigation view
  - Tailwind CSS + MUI/X-Charts integration
- �� ⏳ Pending: Database setup, AI agents pipeline, task queue, frontend API integration

## Key Files & Directories
- `/backend/app/` - Main FastAPI application
- `/backend/app/agents/` - AI agent implementations (context, IOC, graph/state)
- `/backend/app/infrastructure/siem/` - SIEM abstraction and Splunk provider
- `/backend/app/api/v1/endpoints/` - API endpoints (health, alerts, search)
- `/frontend/src/app/` - Next.js App Router pages
- `/frontend/src/components/` - Reusable React components
- `/docs/` - Documentation (DEVELOPMENT_PLAN.md, implementation_plan.md, design.md)