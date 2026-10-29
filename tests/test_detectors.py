from datetime import datetime, timedelta

import pandas as pd

from log_pipeline.detectors import (
    attack_signatures, brute_force, error_bursts, off_hours_login,
    request_rate_outliers, run_detectors, sensitive_sudo, success_after_failures,
)

T0 = datetime(2026, 10, 20, 12, 0, 0)


def auth_df(rows):
    return pd.DataFrame(rows, columns=["timestamp", "event", "user", "ip", "command"])


def failures(ip, n, start=T0, gap=5, user="root"):
    return [(start + timedelta(seconds=i * gap), "failed_password", user, ip, None) for i in range(n)]


def test_brute_force_triggers_above_threshold():
    alerts = brute_force(auth_df(failures("1.1.1.1", 10)), threshold=5, window="5min")
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "1.1.1.1"
    assert alerts[0]["count"] == 10


def test_brute_force_ignores_spread_out_failures():
    # 10 failures, one every 10 minutes, never 5 inside a 5-minute window.
    alerts = brute_force(auth_df(failures("1.1.1.1", 10, gap=600)), threshold=5, window="5min")
    assert alerts == []


def test_success_after_failures_flags_compromise():
    rows = failures("9.9.9.9", 4, user="deploy")
    rows.append((T0 + timedelta(minutes=2), "accepted_login", "deploy", "9.9.9.9", None))
    alerts = success_after_failures(auth_df(rows), min_failures=3)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["user"] == "deploy"


def test_success_after_failures_needs_same_ip():
    rows = failures("9.9.9.9", 4)
    rows.append((T0 + timedelta(minutes=2), "accepted_login", "deploy", "8.8.8.8", None))
    assert success_after_failures(auth_df(rows), min_failures=3) == []


def test_off_hours_login():
    rows = [
        (T0.replace(hour=2), "accepted_login", "a", "1.1.1.1", None),
        (T0.replace(hour=14), "accepted_login", "b", "1.1.1.2", None),
        (T0.replace(hour=23), "accepted_login", "c", "1.1.1.3", None),
    ]
    alerts = off_hours_login(auth_df(rows))
    assert sorted(a["user"] for a in alerts) == ["a", "c"]


def test_sensitive_sudo():
    rows = [
        (T0, "sudo_command", "deploy", None, "/bin/cat /etc/shadow"),
        (T0, "sudo_command", "akshat", None, "/usr/bin/apt update"),
    ]
    alerts = sensitive_sudo(auth_df(rows))
    assert len(alerts) == 1 and alerts[0]["user"] == "deploy"


def access_df(rows):
    return pd.DataFrame(rows, columns=["timestamp", "ip", "path", "status"])


def test_request_rate_outlier():
    rows = []
    for c in range(20):
        rows += [(T0, f"10.0.0.{c}", "/", 200)] * 5
    rows += [(T0, "6.6.6.6", "/", 200)] * 300
    alerts = request_rate_outliers(access_df(rows), z_threshold=3.0)
    assert [a["ip"] for a in alerts] == ["6.6.6.6"]


def test_error_burst():
    rows = [(T0 + timedelta(seconds=i), "5.5.5.5", f"/p{i}", 404) for i in range(15)]
    rows += [(T0, "1.1.1.1", "/missing", 404)]
    alerts = error_bursts(access_df(rows), threshold=10, window="1min")
    assert [a["ip"] for a in alerts] == ["5.5.5.5"]


def test_attack_signatures():
    rows = [
        (T0, "7.7.7.7", "/item?id=1%20UNION%20SELECT%20password", 400),
        (T0, "7.7.7.7", "/../../etc/passwd", 400),
        (T0, "1.1.1.1", "/dashboard", 200),
    ]
    rules = {a["rule"] for a in attack_signatures(access_df(rows))}
    assert {"sql_injection", "path_traversal"} <= rules


def test_run_detectors_sorts_by_severity():
    rows = failures("9.9.9.9", 6, user="deploy")
    rows.append((T0.replace(hour=23), "accepted_login", "deploy", "9.9.9.9", None))
    rows.append((T0 + timedelta(minutes=1), "accepted_login", "deploy", "9.9.9.9", None))
    out = run_detectors(auth_df(rows), "auth")
    assert out.iloc[0]["severity"] == "critical"


def test_run_detectors_empty():
    out = run_detectors(pd.DataFrame(), "auth")
    assert out.empty
