"""Behavioural anomaly detection: per-IP profiles scored with Isolation Forest."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from .parsers import Event

PROFILE_FEATURES = [
    "events", "web_requests", "error_ratio", "not_found_ratio", "unique_paths", "path_diversity",
    "mean_bytes", "max_bytes", "failed_logins", "unique_users", "night_ratio", "distinct_agents",
    "requests_per_minute",
]


@dataclass
class Anomaly:
    ip: str
    score: float
    top_deviations: list[tuple[str, float, float]]   # (feature, value, z-score)

    def as_dict(self) -> dict:
        return {"ip": self.ip, "score": round(self.score, 4),
                "why": [{"feature": f, "value": round(v, 3), "z": round(z, 2)} for f, v, z in self.top_deviations]}


def profiles(events: list[Event]) -> tuple[list[str], np.ndarray]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)
    ips, rows = [], []
    for ip, evs in by_ip.items():
        web = [e for e in evs if e.action == "http"]
        n_web = max(len(web), 1)
        span_min = max((evs[-1].ts - evs[0].ts).total_seconds() / 60, 1.0)
        paths = {e.path.split("?")[0] for e in web}
        rows.append([
            len(evs), len(web),
            sum(e.status >= 400 for e in web) / n_web,
            sum(e.status == 404 for e in web) / n_web,
            len(paths), len(paths) / n_web,
            float(np.mean([e.bytes for e in web])) if web else 0.0,
            float(max((e.bytes for e in web), default=0)),
            sum(e.action in {"login_failed", "invalid_user"} for e in evs),
            len({e.user for e in evs if e.user}),
            sum(e.ts.hour < 6 for e in evs) / len(evs),
            len({e.agent for e in web}),
            len(evs) / span_min,
        ])
        ips.append(ip)
    return ips, np.asarray(rows, dtype=float).reshape(-1, len(PROFILE_FEATURES))


def detect_anomalies(events: list[Event], contamination: float = 0.03, top_k: int = 3, seed: int = 0) -> list[Anomaly]:
    ips, x = profiles(events)
    if len(ips) < 10:
        return []
    xt = np.log1p(x)
    iso = IsolationForest(n_estimators=300, contamination=contamination, random_state=seed).fit(xt)
    flags = iso.predict(xt) == -1
    scores = -iso.score_samples(xt)
    med = np.median(xt, axis=0)
    mad = np.median(np.abs(xt - med), axis=0) * 1.4826            # robust z-scores
    scale = np.where(mad > 0, mad, xt.std(axis=0))                 # fall back when most values are equal
    scale = np.maximum(scale, 0.1)                                  # avoid exploding scores on near-constant features
    out = []
    for i in np.where(flags)[0]:
        z = np.clip((xt[i] - med) / scale, -99, 99)
        top = np.argsort(-z)[:top_k]   # what this IP does *more* than normal is what matters
        out.append(Anomaly(ips[i], float(scores[i]),
                           [(PROFILE_FEATURES[j], float(x[i, j]), float(z[j])) for j in top]))
    return sorted(out, key=lambda a: -a.score)
