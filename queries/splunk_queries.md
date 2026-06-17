# SPL Queries — Investigation 1 (HTTP Web Attack)

## Query 1 — Find Top Source IPs by Traffic Volume
**Purpose:** Identify which IPs made the most HTTP requests — 
high volume from external IP = suspicious

index=botsv3 earliest=0 sourcetype="stream:http"
| stats count by src_ip
| sort -count

**Finding:** 91.207.175.249 (external) made 839 requests — flagged for investigation

---

## Query 2 — Investigate External IP Activity
**Purpose:** See every request made by suspicious IP — 
URLs visited, methods used, response codes

index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| table _time, src_ip, dest_ip, uri_path, status, http_method
| sort _time

**Finding:** Requests at millisecond speed — confirmed automated

---

## Query 3 — Analyze URI Paths for Suspicious IP
**Purpose:** See exactly which pages attacker accessed 
and how many times

index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| stats count by uri_path, status
| sort -count

**Finding:** Hitting /attachment.php, /forumdisplay.php — reconnaissance confirmed

---

## Query 4 — Status Code Distribution
**Purpose:** 404s confirm scanning, 304s confirm returning 
attacker, all 200s confirm successful access

index=botsv3 earliest=0 sourcetype="stream:http" src_ip="91.207.175.249"
| stats count by status

**Finding:** 682 success, 155 cached, 2 probes — persistent attacker confirmed

---

## Query 5 — Find File Upload Attempts
**Purpose:** POST to attachment.php = file upload attempt 
= potential web shell plant

index=botsv3 earliest=0 sourcetype="stream:http"
uri_path="/attachment.php" http_method=POST
| table _time, src_ip, uri_path, status, http_method
| sort _time

**Finding:** No results — 91.207.175.249 did not upload anything

---

## Query 6 — Detect Automated Scanners (All IPs)
**Purpose:** Zoom out from single IP — find any IP 
repeatedly hitting PHP files across entire dataset

index=botsv3 earliest=0 sourcetype="stream:http"
| where like(uri_path, "%.php%")
| stats count by src_ip, uri_path
| where count > 10
| sort -count

**Finding:** Discovered new suspect 35.182.246.222 hitting every PHP page

---

## Query 7 — Identify Attack Tool via User Agent
**Purpose:** User agent reveals what tool attacker used — 
real browser vs custom script

index=botsv3 earliest=0 sourcetype="stream:http" src_ip="35.182.246.222"
| table _time, uri_path, http_method, status, http_user_agent
| sort _time

**Finding:** __main__/0.2 = custom Python script confirmed

---

## Query 8 — Find All Successful POST Requests
**Purpose:** POST + 200 = someone successfully submitted 
data — login, upload, or command execution

index=botsv3 earliest=0 sourcetype="stream:http"
http_method=POST status=200
| table _time, src_ip, uri_path, status
| sort _time

**Finding:** Multiple external IPs successfully POSTing to /member.php

---

## Query 9 — Investigate Credential Stuffing IPs
**Purpose:** Filter noise (CSS/JS/images) to see only 
meaningful attacker actions after login

index=botsv3 earliest=0 sourcetype="stream:http"
| where src_ip IN ("157.97.121.69","107.77.75.123",
"12.196.122.127","62.251.109.73")
| where NOT like(uri_path, "%.css")
| where NOT like(uri_path, "%.js")
| where NOT like(uri_path, "%.png")
| where NOT like(uri_path, "%.ico")
| table _time, src_ip, uri_path, http_method, status
| sort _time

**Finding:** 12.196.122.127 bulk downloaded 7 attachments in 1 second

---

## Query 10 — Detect User Agent Spoofing
**Purpose:** Same IP switching OS/browser = automated 
tool rotating user agents to evade detection

index=botsv3 earliest=0 sourcetype="stream:http"
uri_path="/member.php" http_method=POST
| table _time, src_ip, status, http_user_agent
| sort _time

**Finding:** 12.196.122.127 switched from iPhone to Mac Firefox 
in 2 minutes — confirmed credential stuffing tool
