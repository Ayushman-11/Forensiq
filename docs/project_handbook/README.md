# Forensiq Project Handbook & Deep-Dive Architecture Guide

Welcome to the **Forensiq Complete Project Handbook**. This documentation suite is designed for anyone—even with **zero prior knowledge of cybersecurity**—to completely understand, operate, navigate, and explain the Forensiq platform from top to bottom.

---

## 🗺️ Documentation Road Map

This documentation is split into dedicated, focused chapters. You can read them in order or jump to any topic you want to understand or explain:

| Guide | File | What It Covers |
|---|---|---|
| **01. High-Level Overview & Core Concepts** | [01_high_level_overview_and_concepts.md](file:///d:/Forensiq/docs/project_handbook/01_high_level_overview_and_concepts.md) | What is Forensiq? What problem does it solve? Plain English explanation of SOCs, SIEMs, Alerts, IOCs, and why traditional methods fail. |
| **02. Architecture & Data Flow** | [02_architecture_and_end_to_end_data_flow.md](file:///d:/Forensiq/docs/project_handbook/02_architecture_and_end_to_end_data_flow.md) | The bird's-eye view. How Splunk, FastAPI, MongoDB, LangGraph, and Next.js connect together. Full ASCII/Mermaid flowcharts. |
| **03. Ingestion & Normalization Engine** | [03_siem_ingestion_and_normalization.md](file:///d:/Forensiq/docs/project_handbook/03_siem_ingestion_and_normalization.md) | How raw logs from Splunk enter the system, how noise is filtered out, how duplicate events are grouped, and how canonical alerts are created. |
| **04. Multi-Agent AI Pipeline (LangGraph)** | [04_multi_agent_investigation_pipeline.md](file:///d:/Forensiq/docs/project_handbook/04_multi_agent_investigation_pipeline.md) | The heart of Forensiq. Deep dive into the 7 autonomous AI agents: Context, Enrichment, Correlation, MITRE, Timeline, Risk, and Playbook Recommendation. |
| **05. Threat Intelligence & Enrichment** | [05_threat_intel_and_enrichment.md](file:///d:/Forensiq/docs/project_handbook/05_threat_intel_and_enrichment.md) | How VirusTotal v3 and AbuseIPDB v2 work. What is an IOC? What is defanging? How reputations and threat scores are calculated and cached. |
| **06. Frontend UI, Visuals & WebSockets** | [06_frontend_ui_visualizations_and_websockets.md](file:///d:/Forensiq/docs/project_handbook/06_frontend_ui_visualizations_and_websockets.md) | The user interface explained. Dashboard, Alerts, Investigations, MITRE Matrix Heatmap, Visual Process Execution Tree, and real-time streaming over WebSockets. |
| **07. PDF Reporting Engine** | [07_pdf_reporting_engine.md](file:///d:/Forensiq/docs/project_handbook/07_pdf_reporting_engine.md) | How server-side ReportLab generates publication-ready Executive Summaries (1-page) and Full Technical Investigation reports directly from the database. |
| **08. Concrete Walkthrough Example** | [08_concrete_case_walkthrough_example.md](file:///d:/Forensiq/docs/project_handbook/08_concrete_case_walkthrough_example.md) | A complete real-world walkthrough: from a hacker running malicious PowerShell to the alert triggering, AI investigating, graph rendering, and final report download. |
| **09. Glossary & Cheatsheet** | [09_glossary_and_interview_qa.md](file:///d:/Forensiq/docs/project_handbook/09_glossary_and_interview_qa.md) | Easy definitions of 30+ cybersecurity terms (SIEM, TTP, Sysmon, C2, Hash, EDR, etc.) plus 15 frequently asked questions and how to answer them in an interview or demo. |

---

## 💡 Quick Elevator Pitch

> **"Forensiq is an Autonomous AI-Agent driven Security Operations Center (SOC) investigation platform. It connects to enterprise log engines like Splunk, automatically detects cyber threats, uses a 7-agent AI pipeline to investigate the incident in real-time, displays interactive MITRE ATT&CK heatmaps and process execution DAG trees, and compiles downloadable executive PDF reports in seconds."**

Proceed to [Chapter 1: High-Level Overview & Core Concepts](file:///d:/Forensiq/docs/project_handbook/01_high_level_overview_and_concepts.md) to begin.
