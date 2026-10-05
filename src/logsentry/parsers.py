"""Parsers for common security-relevant log formats into a single Event model."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class Event:
    ts: datetime
    source: str            # "auth" | "web" | "json"
    ip: str
    action: str            # login_failed | login_ok | invalid_user | http
    user: str = ""
    status: int = 0
    method: str = ""
    path: str = ""
    bytes: int = 0
    agent: str = ""


# Linux sshd (syslog format):  "Oct  5 03:12:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
SYSLOG = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")

# Combined log format (nginx / apache)
COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "[^"]*" "(?P<agent>[^"]*)")?')


def parse_auth_line(line: str, year: int = 2026) -> Event | None:
    m = SYSLOG.match(line.strip())
    if not m:
        return None
    hh, mm, ss = map(int, m["time"].split(":"))
    ts = datetime(year, MONTHS.get(m["mon"], 1), int(m["day"]), hh, mm, ss)
    msg = m["msg"]
    for regex, action in ((FAILED, "login_failed"), (ACCEPTED, "login_ok"), (INVALID, "invalid_user")):
        hit = regex.search(msg)
        if hit:
            return Event(ts, "auth", hit["ip"], action, user=hit["user"])
    return None


def parse_web_line(line: str) -> Event | None:
    m = COMBINED.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
    return Event(ts, "web", m["ip"], "http", user="" if m["user"] == "-" else m["user"],
                 status=int(m["status"]), method=m["method"], path=m["path"],
                 bytes=0 if m["bytes"] == "-" else int(m["bytes"]), agent=m["agent"] or "")


def parse_json_line(line: str) -> Event | None:
    try:
        d = json.loads(line)
        return Event(datetime.fromisoformat(d["ts"]), "json", d["ip"], d.get("action", "http"),
                     user=d.get("user", ""), status=int(d.get("status", 0)), method=d.get("method", ""),
                     path=d.get("path", ""), bytes=int(d.get("bytes", 0)), agent=d.get("agent", ""))
    except (ValueError, KeyError, TypeError):
        return None


def parse_lines(lines: Iterable[str]) -> Iterator[Event]:
    """Auto-detect the format line by line; unparseable lines are skipped."""
    for line in lines:
        if not line.strip():
            continue
        for fn in (parse_web_line, parse_auth_line, parse_json_line):
            ev = fn(line)
            if ev:
                yield ev
                break


def parse_files(paths: Iterable[str]) -> list[Event]:
    events: list[Event] = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            events.extend(parse_lines(f))
    return sorted(events, key=lambda e: e.ts)
