# LogSentry — Security Log Analytics & Anomaly Detection

> Turns raw Linux `auth.log` and nginx/Apache access logs into prioritised, MITRE ATT&CK-mapped alerts. It uses **detection rules** for known attack patterns and an **Isolation Forest** over per-IP behaviour profiles for everything else, and explains why each IP is anomalous.

[![CI](https://github.com/ZakariaHibaoui2/log-anomaly-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/log-anomaly-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo

`logsentry demo` writes a day of realistic logs (120 normal visitors, admins with password typos) with **5 injected attack scenarios**, then scans them:

```text
Parsed 4397 events {'web': 4318, 'auth': 79}

RULE ALERTS (9)
  CRITICAL compromise_after_bruteforce  203.0.113.10    x1    T1078      successful login as 'root' after a brute-force burst
  HIGH     ssh_bruteforce               203.0.113.10    x51   T1110.001  10 failed logins in 0:10:00 users=root
  HIGH     password_spraying            203.0.113.20    x6    T1110.003  5 accounts tried in 0:10:00 users=admin,alice,bob,...
  HIGH     sql_injection_attempt        198.51.100.8    x1    T1190      SQLi pattern: /products?id=1%27%20OR%201=1--
  HIGH     path_traversal               198.51.100.8    x1    T1083      traversal: /download?file=../../../../etc/passwd
  MEDIUM   sensitive_file_probe         198.51.100.7    x6    T1595.003  probe: /.env
  MEDIUM   scanner_user_agent           198.51.100.7    x43   T1595      tool UA: sqlmap/1.8.2#stable
  MEDIUM   web_scanner                  198.51.100.7    x19   T1595.003  25/25 requests returned 404
  MEDIUM   xss_attempt                  198.51.100.8    x1    T1189      XSS pattern: /search?q=<script>alert(1)</script>

BEHAVIOURAL ANOMALIES (4)
  198.51.100.9     score=0.779  requests_per_minute=120 (z=+40.8); mean_bytes=99542 (z=+12.6); max_bytes=119916 (z=+11.4)
  198.51.100.7     score=0.779  requests_per_minute=43 (z=+30.7); not_found_ratio=1 (z=+6.9); error_ratio=1 (z=+6.9)
  203.0.113.10     score=0.759  requests_per_minute=26.3 (z=+26.0); failed_logins=60 (z=+9.7); night_ratio=1 (z=+5.2)
  203.0.113.20     score=0.747  unique_users=10 (z=+9.5); requests_per_minute=2.9 (z=+6.5); failed_logins=10 (z=+5.6)
```

**All 5 scenarios are detected with zero alerts on the 120 legitimate users.** The data-scraping IP (`198.51.100.9`) triggers no signature at all, since it uses valid URLs with status 200. Only the behavioural model catches it, through its request rate and response volume.

## Detections

| Rule | Severity | ATT&CK | Logic |
|---|---|---|---|
| `compromise_after_bruteforce` | critical | T1078 | successful login from an IP that just brute-forced |
| `ssh_bruteforce` | high | T1110.001 | ≥ 10 failures / 10 min / IP |
| `password_spraying` | high | T1110.003 | ≥ 5 distinct accounts / 10 min / IP |
| `sql_injection_attempt` | high | T1190 | `UNION SELECT`, `OR 1=1`, `'--`, `sleep(`, … (URL-encoded too) |
| `path_traversal` | high | T1083 | `../`, `%2e%2e/`, `/etc/passwd`, `win.ini` |
| `xss_attempt` | medium | T1189 | `<script`, `javascript:`, `onerror=` |
| `sensitive_file_probe` | medium | T1595.003 | `/.env`, `/.git/`, `wp-config.php`, `phpmyadmin`, backups |
| `scanner_user_agent` | medium | T1595 | sqlmap, nikto, nmap, gobuster, nuclei, … |
| `web_scanner` | medium | T1595.003 | ≥ 25 × 404 and ≥ 60% 404 ratio / 10 min |
| `root_login` | medium | T1078.003 | direct root login |

**Behavioural model:** 13 features per IP (request volume and rate, error/404 ratios, path diversity, bytes, failed logins, distinct users, night-time ratio, user-agents) → log-scaled → Isolation Forest. Explanations use **robust z-scores** (median / MAD) and show what the IP does *more* than normal.

## Usage

```bash
pip install -e ".[dev]"
logsentry demo                                   # generate + scan sample logs
logsentry scan /var/log/auth.log /var/log/nginx/access.log
logsentry scan --json app-events.jsonl > findings.json
```

Supported inputs (auto-detected per line):
- Linux sshd syslog lines (`Failed password`, `Accepted …`, `Invalid user`)
- nginx / Apache **combined** access log format
- JSON lines `{"ts": "...", "ip": "...", "action": "login_failed|login_ok|http", "user", "status", "path", "bytes", "agent"}`

## Project structure

```
src/logsentry/
├── parsers.py    # auth.log / combined / JSON → Event
├── rules.py      # sliding-window detections with MITRE mapping
├── anomaly.py    # per-IP profiles, Isolation Forest, robust explanations
├── simulate.py   # realistic logs with labelled attack scenarios (TEST-NET IPs)
└── cli.py        # scan / demo
tests/            # 15 tests: parsers, every rule, end-to-end scenario coverage, no false positives
```

## License

[MIT](LICENSE)
