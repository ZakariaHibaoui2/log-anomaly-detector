from datetime import datetime, timedelta

import pytest

from logsentry.anomaly import detect_anomalies
from logsentry.cli import main, scan
from logsentry.parsers import Event, parse_auth_line, parse_files, parse_json_line, parse_web_line
from logsentry.rules import detect
from logsentry.simulate import SCENARIOS, simulate


def test_parse_auth_lines():
    e = parse_auth_line("Oct  5 03:12:01 web01 sshd[811]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2")
    assert e.action == "login_failed" and e.user == "admin" and e.ip == "1.2.3.4" and e.ts.hour == 3
    ok = parse_auth_line("Oct  5 03:15:00 web01 sshd[812]: Accepted publickey for bob from 10.0.0.2 port 5 ssh2")
    assert ok.action == "login_ok" and ok.user == "bob"
    assert parse_auth_line("Oct  5 03:15:00 web01 CRON[1]: session opened") is None


def test_parse_web_line():
    line = '10.1.2.3 - - [05/Oct/2026:10:00:00 +0000] "GET /a?b=1 HTTP/1.1" 404 512 "-" "curl/8.0"'
    e = parse_web_line(line)
    assert (e.ip, e.status, e.path, e.bytes, e.agent) == ("10.1.2.3", 404, "/a?b=1", 512, "curl/8.0")


def test_parse_json_line():
    e = parse_json_line('{"ts": "2026-10-05T10:00:00", "ip": "1.1.1.1", "action": "login_failed", "user": "x"}')
    assert e.action == "login_failed"
    assert parse_json_line("not json") is None


def _fails(ip, n, users=("root",), start=datetime(2026, 1, 1)):
    return [Event(start + timedelta(seconds=i), "auth", ip, "login_failed", user=users[i % len(users)])
            for i in range(n)]


def test_bruteforce_and_compromise():
    evs = _fails("5.5.5.5", 12)
    evs.append(Event(evs[-1].ts + timedelta(seconds=3), "auth", "5.5.5.5", "login_ok", user="root"))
    rules = {a.rule for a in detect(evs)}
    assert {"ssh_bruteforce", "compromise_after_bruteforce"} <= rules


def test_below_threshold_is_quiet():
    assert detect(_fails("6.6.6.6", 3)) == []


def test_spraying():
    rules = {a.rule for a in detect(_fails("7.7.7.7", 8, users=("a", "b", "c", "d", "e", "f")))}
    assert "password_spraying" in rules


@pytest.mark.parametrize("path,rule", [
    ("/p?id=1%27%20OR%201=1--", "sql_injection_attempt"),
    ("/s?q=<script>alert(1)</script>", "xss_attempt"),
    ("/f?file=../../etc/passwd", "path_traversal"),
    ("/.env", "sensitive_file_probe"),
])
def test_web_signatures(path, rule):
    e = Event(datetime(2026, 1, 1), "web", "9.9.9.9", "http", status=404, path=path)
    assert rule in {a.rule for a in detect([e])}


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    d = tmp_path_factory.mktemp("logs")
    simulate(d)
    return [str(d / "auth.log"), str(d / "access.log")]


def test_simulation_all_scenarios_detected(sample):
    result = scan(sample, as_json=True)
    flagged = {a["ip"] for a in result["alerts"]} | {a["ip"] for a in result["anomalies"]}
    assert set(SCENARIOS) <= flagged


def test_compromise_is_critical(sample):
    alerts = detect(parse_files(sample))
    crit = [a for a in alerts if a.severity == "critical"]
    assert crit and crit[0].ip == "203.0.113.10" and crit[0].mitre == "T1078"


def test_scraper_found_by_anomaly_model(sample):
    anomalies = detect_anomalies(parse_files(sample))
    assert "198.51.100.9" in {a.ip for a in anomalies}
    assert anomalies[0].top_deviations


def test_no_false_alerts_on_normal_users(sample):
    alerts = detect(parse_files(sample))
    assert all(not a.ip.startswith("10.") for a in alerts)


def test_cli_demo(tmp_path, capsys):
    main(["demo", "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert "RULE ALERTS" in out and "compromise_after_bruteforce" in out
