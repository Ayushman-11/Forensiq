# Forensiq Product Design System

## Brand premise

Forensiq is an analyst-first security operations workspace. It turns noisy SIEM telemetry into a short, defensible queue of decisions: what happened, how serious it is, and what to do next.

The interface should feel precise, calm, operational, and trustworthy. It is a working tool for SOC analysts, not a futuristic marketing surface.

## Visual direction

Use a restrained dark operations console with strong hierarchy, compact density, and deliberate severity color. Information should be scannable in seconds. The visual language is technical and serious, with enough warmth in the amber/red states to make urgency obvious.

Avoid generic AI dashboard patterns: no decorative gradients, purple glow, excessive glass, oversized KPI tiles, or charts without an operational decision attached.

## Color system

| Role | Value | Usage |
|---|---|---|
| Background | `#0b0d0f` | Application canvas |
| Surface | `#121619` | Panels and navigation |
| Elevated surface | `#181d20` | Selected rows and controls |
| Border | `#293136` | Dividers and field boundaries |
| Primary text | `#eef2f2` | Titles and values |
| Secondary text | `#93a0a3` | Labels and supporting context |
| Muted text | `#5d6a6e` | Metadata and empty states |
| Accent | `#65c7c2` | Focus, links, healthy system state |
| Critical | `#f05a6e` | Immediate response required |
| High | `#e8a24b` | Priority review |
| Medium | `#6fa8dc` | Investigation signal |
| Success | `#74c69d` | Completed or healthy |

Severity colors are semantic, not decorative. Never use more than one accent color for the same semantic state.

## Typography

- Space Grotesk for headings and navigation.
- JetBrains Mono for timestamps, event IDs, IPs, hashes, and query text.
- Sentence case for user-facing headings.
- Uppercase tracking labels only for compact metadata, never for paragraphs.

## Layout and spacing

- Use a single content column capped around 1440px.
- Prefer one primary work surface per page, with one supporting surface beside it.
- Use 4px base spacing and 8/12/16/24px practical increments.
- Use 4–8px radii. Avoid pill-shaped containers except status badges.
- Borders define structure; shadows are reserved for menus and dialogs.

## Core components

- **Priority card:** one number, one label, one action or explanation.
- **Alert row:** severity, title, target, rule, age, status, and one action. Hide secondary fields until selected.
- **Status badge:** short semantic label with text and color; never color alone.
- **Empty state:** explain what is missing and how to recover.
- **Investigation summary:** risk, confidence, evidence count, and recommendation before raw details.
- **Navigation:** show only shipped destinations. Do not expose placeholder links.

## Motion

Use 120–180ms transitions for selection and menus. Use loading motion only while work is active. Do not animate every row or chart on every refresh.

## Anti-patterns

- Purple or neon glow backgrounds.
- Fake metrics such as hardcoded MTTD or threat-intel counts.
- Decorative charts that do not change an analyst decision.
- Placeholder navigation links.
- Nested cards inside cards without a clear hierarchy.
- Calling deterministic heuristics “AI” when no model was used.

## Implementation notes

Design tokens live in `frontend/src/app/globals.css`. Product pages should use the semantic classes and palette above. The dashboard and alert queue are the primary surfaces; new pages should extend their patterns rather than inventing independent visual systems.
