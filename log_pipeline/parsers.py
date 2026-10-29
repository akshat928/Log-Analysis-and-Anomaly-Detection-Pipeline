"""Regex parsers that turn raw log lines into structured records.

Supported formats:
  - auth: Linux syslog auth logs (sshd, sudo), e.g. /var/log/auth.log
  - access: Apache/Nginx combined access logs
"""

import re
from datetime import datetime

import pandas as pd

# --- auth.log -----------------------------------------------------------------

_SYSLOG_PREFIX = r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
SYSLOG_RE = re.compile(_SYSLOG_PREFIX)

AUTH_PATTERNS = [
    ("failed_password", re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+")),
    ("accepted_login", re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+")),
    ("invalid_user", re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")),
    ("sudo_command", re.compile(
        r"^\s*(?P<user>\S+) : .*COMMAND=(?P<command>.+)$")),
    ("session_opened", re.compile(
        r"session opened for user (?P<user>\S+)")),
]

# --- access.log ---------------------------------------------------------------

ACCESS_RE = re.compile(
    r'^(?P<ip>[\d.]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_auth_line(line: str, year: int) -> dict | None:
    """Parse one auth.log line. Returns None for lines that don't match a known event."""
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    msg = m.group("message")
    for event, pattern in AUTH_PATTERNS:
        em = pattern.search(msg)
        if em:
            fields = em.groupdict()
            ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
            return {
                "timestamp": ts,
                "host": m.group("host"),
                "process": m.group("process"),
                "event": event,
                "user": fields.get("user"),
                "ip": fields.get("ip"),
                "command": fields.get("command"),
            }
    return None


def parse_access_line(line: str) -> dict | None:
    """Parse one combined-format access log line."""
    m = ACCESS_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "timestamp": datetime.strptime(d["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None),
        "ip": d["ip"],
        "user": None if d["user"] == "-" else d["user"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "size": 0 if d["size"] == "-" else int(d["size"]),
        "agent": d.get("agent") or "",
    }


def parse_file(path: str, fmt: str, year: int | None = None) -> tuple[pd.DataFrame, int]:
    """Parse a log file into a DataFrame. Returns (records, number of unparsed lines)."""
    year = year or datetime.now().year
    records, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            rec = parse_auth_line(line, year) if fmt == "auth" else parse_access_line(line)
            if rec is None:
                skipped += 1
            else:
                records.append(rec)
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df, skipped
