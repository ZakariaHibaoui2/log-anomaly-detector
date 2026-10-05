"""Signature and threshold detections (sliding windows per source IP)."""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parsers import Event

SQLI = re.compile(r"(union(\s|%20|\+)+select|or(\s|%20|\+)+1=1|'--|%27|sleep\(|information_schema)", re.I)
XSS = re.compile(r"(<script|%3cscript|javascript:|onerror=|onload=)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|win\.ini)", re.I)
SENSITIVE = re.compile(r"(/\.env|/\.git/|/wp-config\.php|/phpmyadmin|/server-status|/\.aws/|/backup\.(zip|sql))", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei)", re.I)


@dataclass
class Alert:
    rule: str
    severity: str           # low | medium | high | critical
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    detail: str
    mitre: str = ""
    users: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


@dataclass
class RuleConfig:
    window: timedelta = timedelta(minutes=10)
    bruteforce_failures: int = 10
    spray_users: int = 5
    scan_404: int = 25
    scan_404_ratio: float = 0.6


def detect(events: list[Event], cfg: RuleConfig | None = None) -> list[Alert]:
    cfg = cfg or RuleConfig()
    alerts: dict[tuple[str, str], Alert] = {}

    def raise_alert(rule, sev, ev, detail, mitre, users=()):
        key = (rule, ev.ip)
        if key in alerts:
            a = alerts[key]
            a.count += 1
            a.last_seen = max(a.last_seen, ev.ts)
            a.users = sorted(set(a.users) | set(users))
        else:
            alerts[key] = Alert(rule, sev, ev.ip, ev.ts, ev.ts, 1, detail, mitre, sorted(set(users)))

    fails: dict[str, deque] = defaultdict(deque)
    had_burst: set[str] = set()
    web: dict[str, deque] = defaultdict(deque)

    for ev in events:
        if ev.source in {"auth", "json"} and ev.action in {"login_failed", "invalid_user"}:
            q = fails[ev.ip]
            q.append(ev)
            while q and ev.ts - q[0].ts > cfg.window:
                q.popleft()
            users = {e.user for e in q}
            if len(users) >= cfg.spray_users and len(q) >= cfg.spray_users:
                raise_alert("password_spraying", "high", ev, f"{len(users)} accounts tried in {cfg.window}",
                            "T1110.003", users)
                had_burst.add(ev.ip)
            elif len(q) >= cfg.bruteforce_failures:
                raise_alert("ssh_bruteforce", "high", ev, f"{len(q)} failed logins in {cfg.window}",
                            "T1110.001", users)
                had_burst.add(ev.ip)
        elif ev.action == "login_ok" and ev.ip in had_burst:
            raise_alert("compromise_after_bruteforce", "critical", ev,
                        f"successful login as '{ev.user}' after a brute-force burst", "T1078", [ev.user])
        elif ev.action == "login_ok" and ev.user == "root":
            raise_alert("root_login", "medium", ev, "direct root login", "T1078.003", ["root"])

        if ev.source == "web" or ev.action == "http":
            path = ev.path
            if SQLI.search(path):
                raise_alert("sql_injection_attempt", "high", ev, f"SQLi pattern: {path[:80]}", "T1190")
            if XSS.search(path):
                raise_alert("xss_attempt", "medium", ev, f"XSS pattern: {path[:80]}", "T1189")
            if TRAVERSAL.search(path):
                raise_alert("path_traversal", "high", ev, f"traversal: {path[:80]}", "T1083")
            if SENSITIVE.search(path):
                raise_alert("sensitive_file_probe", "medium", ev, f"probe: {path[:80]}", "T1595.003")
            if SCANNER_UA.search(ev.agent):
                raise_alert("scanner_user_agent", "medium", ev, f"tool UA: {ev.agent[:60]}", "T1595")
            q = web[ev.ip]
            q.append(ev)
            while q and ev.ts - q[0].ts > cfg.window:
                q.popleft()
            n404 = sum(e.status == 404 for e in q)
            if n404 >= cfg.scan_404 and n404 / len(q) >= cfg.scan_404_ratio:
                raise_alert("web_scanner", "medium", ev, f"{n404}/{len(q)} requests returned 404", "T1595.003")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts.values(), key=lambda a: (order[a.severity], a.first_seen))
