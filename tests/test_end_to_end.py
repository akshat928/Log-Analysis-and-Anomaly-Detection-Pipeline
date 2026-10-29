"""Runs the full pipeline on the bundled sample logs and checks each planted attack is found."""

from pathlib import Path

from log_pipeline.detectors import run_detectors
from log_pipeline.parsers import parse_file
from log_pipeline.report import write_outputs

DATA = Path(__file__).resolve().parent.parent / "data"


def test_sample_auth_log(tmp_path):
    events, skipped = parse_file(str(DATA / "sample_auth.log"), "auth", 2026)
    assert len(events) > 200
    assert skipped >= 1  # the malformed line and the CRON line
    alerts = run_detectors(events, "auth")
    rules = set(alerts["rule"])
    assert {"brute_force", "success_after_failures", "off_hours_login", "sensitive_sudo"} <= rules
    assert "185.220.101.7" in set(alerts[alerts["rule"] == "brute_force"]["ip"])
    assert "91.240.118.22" in set(alerts[alerts["rule"] == "success_after_failures"]["ip"])
    paths = write_outputs(events, alerts, str(tmp_path))
    assert all(Path(p).exists() for p in paths.values())


def test_sample_access_log():
    events, _ = parse_file(str(DATA / "sample_access.log"), "access")
    alerts = run_detectors(events, "access")
    by_rule = alerts.groupby("rule")["ip"].apply(set).to_dict()
    assert "45.155.205.99" in by_rule["error_burst"]
    assert "20.171.207.5" in by_rule["request_rate_outlier"]
    assert "103.75.190.11" in by_rule["sql_injection"]
    assert "103.75.190.11" in by_rule["path_traversal"]
