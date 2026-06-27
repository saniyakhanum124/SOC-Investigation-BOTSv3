# SPL Queries — Investigation 1 (HTTP Web Attack Analysis)

**Dataset:** Boss of the SOC (BOTS) v3
**Sourcetype:** stream:http
**Analyst:** Saniya
**Date:** August 20, 2018 (attack date) | June 2026 (investigation date)

---

## Query 1 — Identify Top Source IPs by HTTP Traffic Volume

**Purpose:** Baseline analysis — find which IPs made the most HTTP 
requests to identify suspicious high-volume activity. External IPs 
with unusually high counts are flagged for investigation.

**Finding:** 91.207.175.249 (external) made 839 requests — 
flagged as suspicious. 192.168.3.130 (internal) had highest 
overall count of 2207 — flagged for Investigation 2.

```spl
index=botsv3 earliest=0 sourcetype="stream:http"
| stats count by src_ip
| sort -count
```

---

## Query 2 — Investigate Specific External IP Activity

**Purpose:** Deep dive on suspicious IP — see every request made 
chronologically including destination IPs, URI paths, HTTP methods, 
and status codes. Establishes full behavioral profile of the attacker.

**Finding:** Multiple requests within milliseconds of each other — 
confirmed automated behavior, not manual browsing.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| table _time, src_ip, dest_ip, uri_path, status, http_method
| sort _time
```

---

## Query 3 — Analyze URI Paths and Status Codes for Suspicious IP

**Purpose:** Identify which pages the attacker accessed most 
frequently. High counts on sensitive pages like /attachment.php 
indicate targeted reconnaissance.

**Finding:** /attachment.php, /forumdisplay.php, /showthread.php 
accessed repeatedly — confirms systematic forum reconnaissance.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| stats count by uri_path, status
| sort -count
```

---

## Query 4 — Check Status Code Distribution for IP

**Purpose:** Status code breakdown reveals attacker success rate.
- 200 = successfully retrieved content
- 304 = returning visitor (cached) — confirms persistent attacker
- 404 = probed non-existent pages — confirms scanning behavior

**Finding:** 682 success (200), 155 cached (304), 2 probes (404) — 
persistent, returning attacker confirmed.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| stats count by status
```

---

## Query 5 — Check User Agent for Spoofing

**Purpose:** User agent string identifies what tool/browser the 
attacker used. Real browsers show consistent Mozilla/Chrome strings. 
Custom tools or spoofed agents indicate attacker behavior.

**Finding:** Two user agents found — Edge/17.17134 (791 requests) 
and Chrome 67 (48 requests). Real users don't switch browser 
signatures mid-session — confirms spoofing/automated tool.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| stats count by http_user_agent
```

---

## Query 6 — Find File Upload Attempts (POST to attachment.php)

**Purpose:** POST requests to attachment.php indicate file upload 
attempts — potential web shell planting. No results = attacker did 
not upload anything via this page.

**Finding:** No results — 91.207.175.249 did not upload any files. 
Confirms reconnaissance only, no exploitation via file upload.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" 
uri_path="/attachment.php" http_method=POST
| table _time, src_ip, uri_path, status, http_method
| sort _time
```

---

## Query 7 — Find Repeated PHP File Access (Scanner Detection)

**Purpose:** Zoom out from single IP — search entire dataset for 
any IP repeatedly hitting PHP files more than 10 times. This 
discovers new suspicious IPs not yet identified. Running broad 
queries after closing one IP is standard SOC practice to avoid 
tunnel vision.

**Finding:** Discovered new suspect 35.182.246.222 hitting every 
PHP page on the forum — led to Finding 2 investigation.

```spl
index=botsv3 earliest=0 sourcetype="stream:http"
| where like(uri_path, "%.php%")
| stats count by src_ip, uri_path
| where count > 10
| sort -count
```

---

## Query 8 — Analyze Scanner IP Activity and User Agent

**Purpose:** Full behavioral analysis of newly discovered IP — 
timeline, pages accessed, HTTP methods, and crucially the user 
agent string to identify what tool was used.

**Finding:** User agent __main__/0.2 — this is a custom Python 
script. In Python, __main__ identifies the directly executed 
script. No legitimate browser produces this string.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="35.182.246.222"
| table _time, uri_path, http_method, status, http_user_agent
| sort _time
```

---

## Query 9 — Find All Successful POST Requests (Breach Detection)

**Purpose:** POST + status 200 across entire dataset identifies 
every successful data submission — logins, uploads, form 
submissions. This is the broadest breach detection query — 
shows ALL IPs that successfully submitted something.

**Finding:** Multiple external IPs successfully POSTing to 
/member.php — identified the credential stuffing attack group.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" 
http_method=POST status=200
| table _time, src_ip, uri_path, status
| sort _time
```

---

## Query 10 — Confirm Successful Logins by IP (Credential Stuffing)

**Purpose:** Directly counts how many successful POST logins 
each IP achieved on the login page. Cleanest proof of credential 
stuffing — shows all 5 attacker IPs and their individual 
login attempt counts in one table.

**Finding:** 5 external IPs confirmed with successful logins — 
22 total successful POST attempts. 12.196.122.127 had highest 
count at 7 attempts.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" 
uri_path="/member.php" http_method=POST status=200
| stats count by src_ip
```

---

## Query 11 — Analyze User Agents for Spoofing Detection

**Purpose:** Check user agents specifically on login page POST 
requests. Automated credential stuffing tools often rotate user 
agents to evade rate limiting and detection — same IP appearing 
with different OS/browser combinations confirms automation.

**Finding:** 12.196.122.127 switched from iPhone Safari to 
Mac Firefox within 5 minutes — impossible for a real user, 
confirms automated credential stuffing tool.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" 
uri_path="/member.php" http_method=POST
| table _time, src_ip, status, http_user_agent
| sort _time
```

---

## Query 12 — Investigate Post-Login Activity (Filter Noise)

**Purpose:** After identifying credential stuffing IPs, investigate 
what they did after logging in. Filtering out static resources 
(CSS, JS, PNG, ICO) removes noise and reveals only meaningful 
attacker actions — forum pages accessed, files downloaded, 
actions performed.

**Finding:** 12.196.122.127 accessed /showthread.php then 
immediately hit /attachment.php multiple times — bulk download 
behavior confirmed.

```spl
index=botsv3 earliest=0 sourcetype="stream:http"
| where src_ip IN 
  ("157.97.121.69","107.77.75.123","12.196.122.127","62.251.109.73")
| where NOT like(uri_path, "%.css")
| where NOT like(uri_path, "%.js")
| where NOT like(uri_path, "%.png")
| where NOT like(uri_path, "%.ico")
| table _time, src_ip, uri_path, http_method, status
| sort _time
```

---

## Query 13 — Confirm Data Exfiltration via Attachment Downloads

**Purpose:** Isolate all attachment.php activity for the specific 
exfiltrating IP. Shows exact timestamps and count of downloads — 
multiple downloads within same second confirms automated bulk 
download, not manual user behavior.

**Finding:** 14 total downloads across 2 automated bursts — 
7 files at 18:38:57 and 7 files at 18:51:57. Each burst 
completed in under 1 second.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" 
src_ip="12.196.122.127" uri_path="/attachment.php"
| table _time, src_ip, uri_path, http_method, status
| sort _time
```

---

## Query 14 — Investigate Web Shell Scanning IP 1

**Purpose:** Full activity timeline for first web shell scanning 
IP. Looking for PROPFIND (WebDAV probe), GET /webdav/ (directory 
access attempt), and POST to PHP filenames (web shell execution 
attempts). All 404 responses confirm no shells exist on server.

**Finding:** 61.75.35.114 — PROPFIND returned 503, /webdav/ 
returned 404, all PHP shell POSTs returned 404. Attack failed 
completely.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="61.75.35.114"
| table _time, uri_path, http_method, status
| sort _time
```

---

## Query 15 — Investigate Web Shell Scanning IP 2

**Purpose:** Same investigation for second web shell scanning IP. 
Comparing shell name lists between both IPs — if identical, 
suggests same tool or operator coordinating both IPs.

**Finding:** 45.7.231.174 used identical PHP shell name list as 
61.75.35.114 — same tool/operator confirmed. All attempts 
returned 404. Attack failed completely.

```spl
index=botsv3 earliest=0 sourcetype="stream:http" src_ip="45.7.231.174"
| table _time, uri_path, http_method, status
| sort _time
```

---

## Query Reference Summary

| # | Query Name | Finding | Key SPL Commands |
|---|------------|---------|-----------------|
| 1 | Top Source IPs | All | stats, sort |
| 2 | IP Activity Timeline | 1 | table, sort |
| 3 | URI Path Analysis | 1 | stats, sort |
| 4 | Status Code Distribution | 1 | stats |
| 5 | User Agent Check | 1 | stats |
| 6 | File Upload Attempts | 1 | uri_path filter, http_method filter |
| 7 | PHP Scanner Detection | 2 | where like(), stats, where count |
| 8 | Scanner Behavior Analysis | 2 | table, sort |
| 9 | Successful POST Detection | 3 | http_method+status filter |
| 10 | Login Count by IP | 3 | stats count by src_ip |
| 11 | User Agent Rotation | 3 | table, sort |
| 12 | Post-Login Activity | 3, 4 | where IN(), NOT like(), table |
| 13 | Attachment Downloads | 4 | src_ip+uri_path filter |
| 14 | Web Shell Scan IP1 | 5 | table, sort |
| 15 | Web Shell Scan IP2 | 5 | table, sort |

---

*All queries run against index=botsv3 with earliest=0 
(All Time) to capture full BOTS v3 dataset.*

*Investigation 2 queries (Sysmon, WinEventLog, DNS) 
will be added in a separate file upon completion.*
