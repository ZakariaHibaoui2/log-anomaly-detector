"""Generate realistic auth.log + access.log files with labelled attack scenarios (for demos/tests)."""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

PAGES = ["/", "/products", "/products/42", "/cart", "/login", "/about", "/blog/post-1", "/blog/post-2",
         "/static/app.js", "/static/style.css", "/api/items?page=2", "/search?q=shoes", "/contact"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0", "Mozilla/5.0 (Macintosh) Safari/17.4",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari", "Mozilla/5.0 (X11; Linux) Firefox/130.0"]
USERS = ["alice", "bob", "deploy", "carol", "dave"]

# ground truth: ip -> scenario (documentation-only TEST-NET ranges)
SCENARIOS = {
    "203.0.113.10": "ssh_bruteforce_then_success",
    "203.0.113.20": "password_spraying",
    "198.51.100.7": "web_scanner_sqlmap",
    "198.51.100.8": "sqli_and_traversal",
    "198.51.100.9": "data_scraping",
}


def _web(ts: datetime, ip: str, path: str, status: int, size: int, agent: str) -> str:
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def _auth(ts: datetime, msg: str) -> str:
    return f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')} web01 sshd[{random.randint(1000, 9999)}]: {msg}"


def simulate(out_dir: str | Path, seed: int = 3, n_users: int = 120) -> dict[str, str]:
    r = random.Random(seed)
    random.seed(seed)
    start = datetime(2026, 10, 5, 0, 0, 0)
    web, auth = [], []

    # normal visitors spread over the day
    for _ in range(n_users):
        ip = f"10.{r.randint(0, 20)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
        agent = r.choice(AGENTS)
        t = start + timedelta(minutes=r.gauss(14 * 60, 180))
        for _ in range(r.randint(3, 40)):
            t += timedelta(seconds=r.randint(2, 120))
            page = r.choice(PAGES)
            status = 404 if r.random() < 0.03 else 200
            web.append((t, _web(t, ip, page, status, r.randint(400, 40_000), agent)))
    # normal admin logins (with the odd typo)
    for u in USERS:
        t = start + timedelta(hours=r.randint(8, 18), minutes=r.randint(0, 59))
        ip = f"10.0.0.{r.randint(2, 50)}"
        if r.random() < 0.4:
            auth.append((t, _auth(t, f"Failed password for {u} from {ip} port 52144 ssh2")))
            t += timedelta(seconds=20)
        auth.append((t, _auth(t, f"Accepted password for {u} from {ip} port 52144 ssh2")))

    # 1. brute force on root, then success (compromise)
    ip = "203.0.113.10"
    t = start + timedelta(hours=3, minutes=12)
    for i in range(60):
        t += timedelta(seconds=r.randint(1, 4))
        auth.append((t, _auth(t, f"Failed password for root from {ip} port {40000 + i} ssh2")))
    t += timedelta(seconds=5)
    auth.append((t, _auth(t, f"Accepted password for root from {ip} port 40100 ssh2")))

    # 2. password spraying: one password, many users
    ip = "203.0.113.20"
    t = start + timedelta(hours=4)
    for u in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "jenkins", "alice", "bob", "deploy"]:
        t += timedelta(seconds=r.randint(10, 40))
        msg = f"Invalid user {u} from {ip} port 3322" if u not in USERS else \
            f"Failed password for {u} from {ip} port 3322 ssh2"
        auth.append((t, _auth(t, msg)))

    # 3. automated scanner
    ip = "198.51.100.7"
    t = start + timedelta(hours=2)
    for p in ["/.env", "/.git/config", "/wp-config.php", "/phpmyadmin/", "/admin", "/backup.zip", "/server-status"] + \
             [f"/{w}" for w in ["old", "test", "dev", "tmp", "bak", "api/v1", "console", "manager", "cgi-bin"] * 4]:
        t += timedelta(seconds=1)
        web.append((t, _web(t, ip, p, 404, 150, "sqlmap/1.8.2#stable (https://sqlmap.org)")))

    # 4. injection attempts
    ip = "198.51.100.8"
    t = start + timedelta(hours=5)
    for p in ["/products?id=1%27%20OR%201=1--", "/search?q=<script>alert(1)</script>",
              "/download?file=../../../../etc/passwd", "/products?id=1 UNION SELECT username,password FROM users"]:
        t += timedelta(seconds=7)
        web.append((t, _web(t, ip, p, 500, 900, AGENTS[0])))

    # 5. scraping / exfiltration over the API at night
    ip = "198.51.100.9"
    t = start + timedelta(hours=1)
    for i in range(1500):
        t += timedelta(seconds=0.5)
        web.append((t, _web(t, ip, f"/api/items?page={i}", 200, r.randint(80_000, 120_000), "python-requests/2.32")))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "access.log").write_text("\n".join(line for _, line in sorted(web)) + "\n", encoding="utf-8")
    (out / "auth.log").write_text("\n".join(line for _, line in sorted(auth)) + "\n", encoding="utf-8")
    return SCENARIOS
