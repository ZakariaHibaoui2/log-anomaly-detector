"""logsentry command line."""
from __future__ import annotations

import argparse
import json
from collections import Counter

from .anomaly import detect_anomalies
from .parsers import parse_files
from .rules import detect
from .simulate import simulate

SEV_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}


def scan(paths: list[str], as_json: bool = False, color: bool = True) -> dict:
    events = parse_files(paths)
    alerts = detect(events)
    anomalies = detect_anomalies(events)
    result = {
        "events": len(events),
        "sources": dict(Counter(e.source for e in events)),
        "alerts": [a.as_dict() for a in alerts],
        "anomalies": [a.as_dict() for a in anomalies],
    }
    if as_json:
        print(json.dumps(result, indent=2))
        return result
    print(f"Parsed {len(events)} events {result['sources']}\n")
    print(f"RULE ALERTS ({len(alerts)})")
    for a in alerts:
        c, r = (SEV_COLOR[a.severity], "\033[0m") if color else ("", "")
        users = f" users={','.join(a.users[:5])}" if a.users else ""
        print(f"  {c}{a.severity.upper():<9}{r}{a.rule:<29}{a.ip:<16}x{a.count:<5}{a.mitre:<11}{a.detail}{users}")
    print(f"\nBEHAVIOURAL ANOMALIES ({len(anomalies)})")
    for an in anomalies:
        why = "; ".join(f"{f}={v:g} (z={z:+.1f})" for f, v, z in an.top_deviations)
        print(f"  {an.ip:<16} score={an.score:.3f}  {why}")
    return result


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="logsentry", description="Security log anomaly detection")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="analyze log files (auth.log, nginx/apache access logs, JSON lines)")
    s.add_argument("files", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-color", action="store_true")
    d = sub.add_parser("demo", help="generate sample logs with attack scenarios and scan them")
    d.add_argument("--out", default="sample-logs")
    a = p.parse_args(argv)
    if a.cmd == "scan":
        scan(a.files, a.json, not a.no_color)
    else:
        truth = simulate(a.out)
        print(f"generated {a.out}/auth.log and {a.out}/access.log; injected scenarios:")
        for ip, sc in truth.items():
            print(f"  {ip:<16} {sc}")
        print()
        scan([f"{a.out}/auth.log", f"{a.out}/access.log"], color=False)


if __name__ == "__main__":
    main()
