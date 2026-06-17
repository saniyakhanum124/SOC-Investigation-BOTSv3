# Investigation 1 — HTTP Web Attack Analysis

**Date:** August 20, 2018 (BOTS v3 scenario)  
**Analyst:** Saniya  
**Severity:** HIGH  
**Status:** Complete

## Objective
Identify suspicious activity in HTTP web traffic logs 
targeting brewertalk.com

## Findings Summary

| Finding | Attacker IP | Attack Type | MITRE |
|---------|------------|-------------|-------|
| 1 | 91.207.175.249 | Web Reconnaissance | T1595 |
| 2 | 35.182.246.222 | Automated Python Scanner | T1595.003 |
| 3 | Multiple IPs | Credential Stuffing | T1110.004 |
| 4 | 12.196.122.127 | Data Exfiltration | T1530 |
| 5 | 61.75.35.114, 45.7.231.174 | Web Shell Scanning | T1505.003 |

## Key Evidence
- 839 HTTP requests from 91.207.175.249 at millisecond speed
- Custom Python tool identified via __main__/0.2 user agent
- 5 external IPs coordinated credential stuffing on /member.php
- 7 attachments bulk downloaded in under 1 second
- Web shell scanning failed — all 404

## Full Incident Report
See /reports/SOC_Incident_Report_Brewertalk.docx
