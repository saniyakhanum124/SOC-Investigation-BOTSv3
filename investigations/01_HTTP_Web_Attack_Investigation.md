# Investigation 1 — HTTP Web Attack Analysis

**Date:** August 20, 2018 (BOTS v3 scenario)
**Analyst:** Saniya
**Severity:** HIGH
**Status:** Complete — Partial Breach Confirmed

## Objective
Identify and investigate suspicious activity in HTTP web 
traffic logs targeting brewertalk.com (MyBB Forum, 
Apache 2.2.34, Amazon AWS)

## Dataset
- Source: BOTS v3 (Boss of the SOC) — Splunk CTF Dataset
- Total Events Analyzed: 143,661
- Primary Sourcetype: stream:http

## Findings Summary

| # | Attacker IP | Attack Type | Severity | MITRE |
|---|-------------|-------------|----------|-------|
| 1 | 91.207.175.249 | Web Reconnaissance | MEDIUM | T1595, T1592, T1190 |
| 2 | 35.182.246.222 | Automated Python Scanner | HIGH | T1595.003, T1594 |
| 3 | 5 coordinated IPs | Credential Stuffing | CRITICAL | T1110.004, T1078 |
| 4 | 12.196.122.127 | Data Exfiltration | CRITICAL | T1530, T1119 |
| 5 | 61.75.35.114, 45.7.231.174 | Web Shell Scanning | MEDIUM | T1505.003 |

## Key Evidence

**Finding 1:** 91.207.175.249 made 839 requests over 39 minutes 
(18:40-19:19), multiple requests within same millisecond confirming 
automation, using spoofed Edge browser user agent

**Finding 2:** 35.182.246.222 identified via __main__/0.2 user agent 
— custom Python script hitting every PHP page, 197/197 requests 
returned 200 OK (100% success rate)

**Finding 3:** 5 external IPs made 22 successful POST logins to 
/member.php. IP 12.196.122.127 rotated user agents from iPhone 
Safari to Mac Firefox within 5 minutes — confirmed automated tool

**Finding 4:** 12.196.122.127 bulk downloaded 14 forum attachments 
across 2 automated bursts (18:38:57 and 18:51:57), 7 files each 
completed in under 1 second

**Finding 5:** 61.75.35.114 and 45.7.231.174 attempted to locate 
web shells via POST to commonly named PHP backdoor filenames — 
all returned 404, attack failed

## Full Incident Report
See `/reports/SOC_Incident_Report_Brewertalk.pdf`

## Screenshots
See `/screenshots/` folder — all evidence screenshots labeled by finding
