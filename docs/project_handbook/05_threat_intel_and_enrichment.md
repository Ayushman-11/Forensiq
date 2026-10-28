# Chapter 5: Threat Intelligence & Enrichment Engine

When a security alert contains an IP address, domain, or file hash, an analyst cannot tell just by looking at it whether it is safe or harmful. 

This chapter explains how Forensiq connects to global threat databases, enriches Indicators of Compromise (IOCs), calculates reputation scores, and protects analysts through automated defanging.

---

## 1. What is Threat Intelligence Enrichment?

Imagine a stranger walks into an office lobby and claims they are an IT repairman. You don't take their word for it—you check their ID against a database of authorized contractors or known security watchlists.

In cybersecurity, **Threat Intelligence Enrichment** does the exact same thing:
- When Forensiq sees an outbound network connection to `194.26.29.112`, it immediately asks global security databases:
  - *"Has this IP address been caught spreading ransomware in the last 30 days?"*
  - *"How many security companies have flagged this IP as malicious?"*
  - *"Which country and Autonomous System Number (ASN) owns it?"*

Forensiq integrates with two world-class threat intelligence APIs ([`backend/app/infrastructure/threat_intel/`](file:///d:/Forensiq/backend/app/infrastructure/threat_intel/)):

### 1. VirusTotal v3 API (`virustotal.py`)
- VirusTotal is owned by Google. It aggregates over **70 antivirus scanners and URL analysis tools** (Kaspersky, CrowdStrike, Sophos, Microsoft Defender, etc.).
- When Forensiq sends a file hash or domain to VirusTotal, VirusTotal returns a breakdown:
  - e.g., `58 / 72 engines detected this file as Trojan.Downloader`.
- Forensiq converts this ratio into an objective threat score.

### 2. AbuseIPDB v2 API (`abuseipdb.py`)
- AbuseIPDB is a community-driven database where network administrators and automated honeypots report abusive IP addresses conducting brute force attacks, port scanning, and spam.
- AbuseIPDB returns an **Abuse Confidence Score (0–100%)**:
  - `0%`: Clean or internal IP.
  - `20–50%`: Suspicious activity reported.
  - `80–100%`: Known malicious scanner or active command-and-control server.

---

## 2. Smart Caching: Why and How

External threat intelligence APIs impose strict rate limits and quotas (especially on free/community keys). If an alert contains 20 IP addresses and you query them on every single page refresh, your API quota will be exhausted in minutes.

Forensiq implements an automated **MongoDB Caching Layer** (`enrichment_cache` collection):

1. **Check Cache First**: Before making an external HTTP request, Forensiq checks if the IOC exists in `enrichment_cache`.
2. **TTL (Time to Live)**: Lookups are valid for **24 hours**. 
3. **Cache Hit**: If found and fresh, the cached score is returned in **under 2 milliseconds** with zero external network overhead.
4. **Cache Miss**: Only if the IOC is not in the cache does Forensiq make an external API request, store the result, and timestamp it.

---

## 3. What is Defanging and Why is it Critical?

If an analyst writes a report or shares a message saying:
> *"The malware downloaded a file from http://evil-attacker.com/payload.exe"*

Someone reading the ticket might accidentally click that link, or an enterprise email security gateway might flag the communication as malicious and quarantine the analyst's email.

### Defanging Rules (`frontend/src/lib/defang.ts`):
Forensiq automatically **defangs** dangerous strings before rendering them or copying them to clipboard:

| Raw (Dangerous) Indicator | Defanged (Safe) Representation | Rule Applied |
|---|---|---|
| `http://malware.com` | `hxxp[://]malware[.]com` | Replace `http` with `hxxp`, bracket protocol and dots |
| `https://c2.cloud` | `hxxps[://]c2[.]cloud` | Replace `https` with `hxxps`, bracket protocol and dots |
| `194.26.29.112` | `194.26.29[.]112` | Bracket the final period of IPv4 addresses |
| `update@phishing.net` | `update[@]phishing[.]net` | Bracket `@` symbol and final dot in emails |

Forensiq also provides a **1-click "Copy Defanged" button** so analysts can paste safely into ticketing systems like Jira or ServiceNow.

---

## 4. The Live IOC Hover Card Component

In the Forensiq UI, whenever an Indicator of Compromise appears (in an alert title, timeline, or evidence panel), it is wrapped in an interactive component called `<IocHoverCard />` ([`frontend/src/components/enrichment/IocHoverCard.tsx`](file:///d:/Forensiq/frontend/src/components/enrichment/IocHoverCard.tsx)).

### What Happens When You Hover Over an IOC:
1. **Defanged String Box**: Shows the safe `hxxp[://]` or `[.]` string with a one-click copy button.
2. **Reputation Badge**: Clearly colored status tag:
   - 🔴 **MALICIOUS**: Confirmed threat (`threat_score > 70`).
   - 🟡 **SUSPICIOUS**: Questionable reputation (`threat_score 30–70`).
   - 🟢 **CLEAN**: Known benign asset or CDN.
3. **Threat Confidence Meter**: Visual horizontal progress bar showing the score out of 100.
4. **Pivot Actions**:
   - **"Pivot to SPL"**: 1-click button that navigates directly to the Splunk search page with `search "<IOC>"` pre-populated.
   - **"VirusTotal"**: Opens the live external analysis page on virustotal.com in a new tab.
   - **"AbuseIPDB"**: Direct link to the IP's report history on abuseipdb.com.

---

*Next Chapter: [Chapter 6: Frontend UI, Visualizations & WebSockets](file:///d:/Forensiq/docs/project_handbook/06_frontend_ui_visualizations_and_websockets.md)*
