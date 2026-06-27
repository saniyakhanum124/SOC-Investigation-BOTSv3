# SOC Threat Investigation Lab — Boss of the SOC v3

## Overview
A hands-on SOC L1 investigation project analyzing real-world 
cyberattack scenarios using Splunk Enterprise SIEM and the 
BOTS v3 (Boss of the SOC) dataset containing 143,661 security 
events across 63 sourcetypes.

All findings were independently verified against raw Splunk 
data before being documented — not copied from walkthroughs 
or answer keys.

## Tools & Technologies
- Splunk Enterprise 9.x (Windows host machine)
- Boss of the SOC (BOTS) v3 Dataset — Official Splunk CTF Dataset
- MITRE ATT&CK Framework
- SPL (Search Processing Language)

---

## Investigation 1 — HTTP Web Attack Analysis

**Target:** www.brewertalk.com (MyBB Forum, Apache 2.2.34, Amazon AWS)
**Attack Date:** August 20, 2018
**Severity:** HIGH
**Status:** Complete — Partial Breach Confirmed

### Findings Summary

| # | Attacker IP | Attack Type | Severity | MITRE Techniques |
|---|-------------|-------------|----------|-----------------|
| 1 | 91.207.175.249 | Web Reconnaissance | MEDIUM | T1595, T1592, T1190 |
| 2 | 35.182.246.222 | Automated Python Scanner | HIGH | T1595.003, T1594, T1587.001 |
| 3 | 5 coordinated IPs | Credential Stuffing | CRITICAL | T1110.004, T1078, T1090 |
| 4 | 12.196.122.127 | Data Exfiltration | CRITICAL | T1530, T1119, T1078 |
| 5 | 61.75.35.114, 45.7.231.174 | Web Shell Scanning (Failed) | MEDIUM | T1505.003, T1595 |

### Attack Timeline

| Time (2018-08-20) | IP | Activity | Result |
|-------------------|----|----------|--------|
| 18:34 – 18:47 | 35.182.246.222 | Python script crawls entire forum | Success — site mapped |
| 18:37 – 19:17 | 5 coordinated IPs | Credential stuffing /member.php — 22 successful logins | Success — accounts compromised |
| 18:38:57 | 12.196.122.127 | Burst 1 — 7 attachments downloaded in <1 second | Success — data exfiltrated |
| 18:38 | 157.97.121.69 | Rapid AJAX POSTs to /xmlhttp.php | Success — forum manipulation |
| 18:40 – 19:19 | 91.207.175.249 | Browser-spoofed reconnaissance — 839 requests over 39 minutes | Success — site mapped |
| 18:51:57 | 12.196.122.127 | Burst 2 — 7 more attachments downloaded in <1 second | Success — data exfiltrated |
| 20:11 – 20:26 | 61.75.35.114, 45.7.231.174 | Web shell scanning — POST to PHP backdoor filenames | Failed — all 404 |

### Key Evidence Highlights

**Finding 1 — Web Reconnaissance:**
- 839 HTTP requests over 39 minutes (18:40:27 to 19:19:53)
- Multiple requests within same millisecond — confirms automation
- Two user agent signatures used (Edge 17.17134 × 791, Chrome 67 × 48)
- Spoofed browser to blend with legitimate traffic

**Finding 2 — Automated Python Scanner:**
- User agent `__main__/0.2` — custom Python script, not a real browser
- 197 out of 197 requests returned 200 OK (100% success — inhuman)
- Systematically hit every PHP page in sequential order

**Finding 3 — Credential Stuffing:**
- 5 external IPs generated 22 successful POST logins to /member.php
- IP 12.196.122.127 rotated user agents from iPhone Safari → Mac Firefox 
  within 5 minutes — confirms automated tool behavior
- Shared Edge/17.17134 user agent across multiple IPs suggests 
  coordinated infrastructure

**Finding 4 — Data Exfiltration:**
- 14 forum attachments bulk downloaded across 2 automated bursts
- Burst 1: 7 files at 18:38:57 (under 1 second)
- Burst 2: 7 files at 18:51:57 (under 1 second)
- Overlapping timeline with login attempts suggests prior session 
  access or unauthenticated guest access vulnerability in MyBB

**Finding 5 — Web Shell Scanning:**
- Both IPs used identical PHP shell name list — suggests same tool/operator
- All POST attempts returned 404 — no pre-existing shells found
- PROPFIND (WebDAV) also returned 503 — no WebDAV access available
- Attack completely failed

### SPL Queries
See `/queries/splunk_queries.md` — all 15 SPL queries with 
purpose explanations

### Evidence Screenshots
See `/screenshots/` — all evidence labeled by finding number

### Full Incident Report
See `/reports/SOC_Incident_Report_Brewertalk.pdf` — 
13-page professional incident response report including 
executive summary, evidence tables, MITRE ATT&CK mapping, 
and recommendations

---

## Investigations In Progress

- **Investigation 2** — Compromised Internal Machine Analysis
  - Target: 192.168.3.130 (highest internal HTTP traffic — 2207 requests)
  - Focus: Malware beaconing, C2 communication, Windows Event Log analysis
  - Sourcetypes: wineventlog:security, Sysmon, stream:dns

- **Investigation 3** — DNS C2 Beaconing Detection
  - Focus: Regular DNS queries to suspicious domains, DNS tunneling
  - Sourcetype: stream:dns

- **Investigation 4** — Windows Event Log Threat Hunting
  - Focus: Failed logins (Event ID 4625), privilege escalation (Event ID 4732)
  - Sourcetype: wineventlog:security

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Found In |
|---|---|---|---|
| T1595 | Active Scanning | Reconnaissance | Findings 1, 2, 5 |
| T1592 | Gather Victim Host Info | Reconnaissance | Finding 1 |
| T1594 | Search Victim-Owned Websites | Reconnaissance | Finding 2 |
| T1587.001 | Develop Capabilities | Resource Development | Finding 2 |
| T1190 | Exploit Public Facing Application | Initial Access | Findings 1, 5 |
| T1110.004 | Credential Stuffing | Credential Access | Finding 3 |
| T1078 | Valid Accounts | Initial Access / Defense Evasion | Findings 3, 4 |
| T1505.003 | Web Shell | Persistence | Finding 5 (attempted) |
| T1119 | Automated Collection | Collection | Finding 4 |
| T1530 | Data from Cloud Storage | Exfiltration | Finding 4 |

---

## Skills Demonstrated
- Splunk SPL query writing and analysis
- HTTP traffic log analysis
- Attacker IP profiling and behavioral analysis
- User agent fingerprinting and spoofing detection
- Evidence verification — all findings cross-checked against raw data
- MITRE ATT&CK TTP mapping
- Structured Incident Response documentation
- Attack chain reconstruction

---

## Repository Structure
