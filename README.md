# SOC Threat Investigation Lab — Boss of the SOC v3

## Overview
A hands-on SOC L1 investigation project analyzing real-world 
cyberattack scenarios using Splunk SIEM and the BOTS v3 dataset 
containing 143,000+ security events.

## Tools & Technologies
- Splunk Enterprise 9.x (Windows host)
- Boss of the SOC (BOTS) v3 Dataset
- MITRE ATT&CK Framework

## Investigations Completed

### Investigation 1 — HTTP Web Attack Analysis
Analyzed 143,000+ HTTP events to identify and trace a 
multi-stage attack against brewertalk.com

**Attacks Found:**
- Web Reconnaissance (T1595)
- Automated Python Scanner (T1595.003)
- Credential Stuffing — 5 coordinated IPs (T1110.004)
- Data Exfiltration via compromised account (T1530)
- Web Shell scanning attempts (T1505.003)

**Key SPL Skills Used:**
- stats, sort, table, where, like()
- Filtering by sourcetype, src_ip, http_method, status
- User agent analysis for attacker tool identification

## Investigations In Progress
- Investigation 2 — Compromised Internal Machine (192.168.3.130)
- Investigation 3 — DNS C2 Beaconing Detection
- Investigation 4 — Windows Event Log Threat Hunting

## Repository Structure
- `/investigations` — Detailed markdown reports per investigation
- `/queries` — All SPL queries used with explanations
- `/screenshots` — Splunk evidence screenshots
- `/reports` — Full incident response reports

## Skills Demonstrated
- SIEM log analysis (Splunk SPL)
- HTTP traffic analysis
- Attacker IP profiling
- MITRE ATT&CK TTP mapping
- Incident Response documentation
