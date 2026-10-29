"""Anomaly detectors that run over parsed log DataFrames.

Each detector returns a list of alert dicts with a common shape:
  rule, severity, ip, user, first_seen, last_seen, count, details
"""

from urllib.parse import unquote

import pandas as pd

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _alert(rule, severity, first, last, count, details, ip=None, user=None) -> dict:
    return {
        "rule": rule,
        "severity": severity,
        "ip": ip,
        "user": user,
        "first_seen": pd.Timestamp(first),
        "last_seen": pd.Timestamp(last),
        "count": int(count),
        "details": details,
    }


# --- auth log detectors -------------------------------------------------------

def brute_force(df: pd.DataFrame, threshold: int = 5, window: str = "5min") -> list[dict]:
    """Many failed logins from one IP inside a sliding time window."""
    failed = df[df["event"].isin(["failed_password", "invalid_user"])]
    alerts = []
    for ip, group in failed.groupby("ip"):
        counts = group.set_index("timestamp").sort_index()["event"].rolling(window).count()
        peak = counts.max()
        if peak >= threshold:
            users = sorted(set(group["user"].dropna()))
            alerts.append(_alert(
                "brute_force", "high", group["timestamp"].min(), group["timestamp"].max(),
                len(group), f"{int(peak)} failures within {window}; users tried: {', '.join(users[:5])}",
                ip=ip,
            ))
    return alerts


def success_after_failures(df: pd.DataFrame, min_failures: int = 3, window: str = "10min") -> list[dict]:
    """A successful login from an IP that just failed several times: possible compromise."""
    alerts = []
    win = pd.Timedelta(window)
    failed = df[df["event"].isin(["failed_password", "invalid_user"])]
    accepted = df[df["event"] == "accepted_login"]
    for _, ok in accepted.iterrows():
        prior = failed[(failed["ip"] == ok["ip"])
                       & (failed["timestamp"] < ok["timestamp"])
                       & (failed["timestamp"] >= ok["timestamp"] - win)]
        if len(prior) >= min_failures:
            alerts.append(_alert(
                "success_after_failures", "critical", prior["timestamp"].min(), ok["timestamp"],
                len(prior) + 1, f"{len(prior)} failures then successful login as '{ok['user']}'",
                ip=ok["ip"], user=ok["user"],
            ))
    return alerts


def off_hours_login(df: pd.DataFrame, start_hour: int = 22, end_hour: int = 6) -> list[dict]:
    """Successful logins outside business hours."""
    ok = df[df["event"] == "accepted_login"]
    hours = ok["timestamp"].dt.hour
    mask = (hours >= start_hour) | (hours < end_hour)
    return [
        _alert("off_hours_login", "medium", r["timestamp"], r["timestamp"], 1,
               f"Login at {r['timestamp']:%H:%M}", ip=r["ip"], user=r["user"])
        for _, r in ok[mask].iterrows()
    ]


def sensitive_sudo(df: pd.DataFrame, keywords: list[str] | None = None) -> list[dict]:
    """sudo commands that touch sensitive files or tools."""
    keywords = keywords or ["/etc/shadow", "/etc/passwd", "useradd", "chmod 777", "nc -e", "wget", "curl"]
    sudo = df[df["event"] == "sudo_command"].dropna(subset=["command"])
    alerts = []
    for _, r in sudo.iterrows():
        hit = next((k for k in keywords if k in r["command"]), None)
        if hit:
            alerts.append(_alert("sensitive_sudo", "high", r["timestamp"], r["timestamp"], 1,
                                 f"sudo matched '{hit}': {r['command'].strip()}", user=r["user"]))
    return alerts


# --- access log detectors -----------------------------------------------------

def request_rate_outliers(df: pd.DataFrame, z_threshold: float = 3.0, min_requests: int = 20) -> list[dict]:
    """IPs whose request volume is a statistical outlier (z-score across all IPs)."""
    counts = df.groupby("ip").size()
    if len(counts) < 3 or counts.std() == 0:
        return []
    z = (counts - counts.mean()) / counts.std()
    alerts = []
    for ip in z[(z >= z_threshold) & (counts >= min_requests)].index:
        rows = df[df["ip"] == ip]
        alerts.append(_alert(
            "request_rate_outlier", "medium", rows["timestamp"].min(), rows["timestamp"].max(),
            counts[ip], f"{counts[ip]} requests (z={z[ip]:.1f}, mean={counts.mean():.1f})", ip=ip,
        ))
    return alerts


def error_bursts(df: pd.DataFrame, threshold: int = 10, window: str = "1min") -> list[dict]:
    """Bursts of 4xx responses from one IP: scanning or directory brute forcing."""
    errors = df[(df["status"] >= 400) & (df["status"] < 500)]
    alerts = []
    for ip, group in errors.groupby("ip"):
        counts = group.set_index("timestamp").sort_index()["status"].rolling(window).count()
        if counts.max() >= threshold:
            alerts.append(_alert(
                "error_burst", "medium", group["timestamp"].min(), group["timestamp"].max(),
                len(group), f"{int(counts.max())} client errors within {window}; "
                            f"{group['path'].nunique()} distinct paths", ip=ip,
            ))
    return alerts


ATTACK_SIGNATURES = {
    "sql_injection": r"(?i)(?:union\s+select|\bor\s+1=1|'--|sleep\()",
    "path_traversal": r"(?:\.\./|\.\.\\)",
    "xss": r"(?i)(?:<script|javascript:|onerror=)",
    "sensitive_file": r"(?i)(?:/\.env\b|wp-config\.php|/etc/passwd|/\.git/)",
}


def attack_signatures(df: pd.DataFrame) -> list[dict]:
    """Requests whose path matches a known attack pattern.

    Paths are URL-decoded first so encoded payloads like %20UNION%20SELECT are caught.
    """
    alerts = []
    decoded = df["path"].fillna("").map(lambda p: unquote(unquote(p)))
    for name, pattern in ATTACK_SIGNATURES.items():
        hits = df[decoded.str.contains(pattern, regex=True)]
        for ip, group in hits.groupby("ip"):
            alerts.append(_alert(
                name, "high", group["timestamp"].min(), group["timestamp"].max(), len(group),
                f"e.g. {group['path'].iloc[0][:80]}", ip=ip,
            ))
    return alerts


AUTH_DETECTORS = [brute_force, success_after_failures, off_hours_login, sensitive_sudo]
ACCESS_DETECTORS = [request_rate_outliers, error_bursts, attack_signatures]


def run_detectors(df: pd.DataFrame, fmt: str, config: dict | None = None) -> pd.DataFrame:
    """Run all detectors for a log format and return alerts sorted by severity then time."""
    config = config or {}
    detectors = AUTH_DETECTORS if fmt == "auth" else ACCESS_DETECTORS
    alerts = []
    if not df.empty:
        for fn in detectors:
            alerts.extend(fn(df, **config.get(fn.__name__, {})))
    cols = ["rule", "severity", "ip", "user", "first_seen", "last_seen", "count", "details"]
    out = pd.DataFrame(alerts, columns=cols)
    if not out.empty:
        out["_rank"] = out["severity"].map(SEVERITY_ORDER)
        out = out.sort_values(["_rank", "first_seen"]).drop(columns="_rank").reset_index(drop=True)
    return out
