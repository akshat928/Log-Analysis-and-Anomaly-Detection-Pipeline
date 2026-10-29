"""Write parsed events and alerts to queryable outputs (CSV, JSON, SQLite)."""

import json
import sqlite3
from pathlib import Path

import pandas as pd


def write_outputs(events: pd.DataFrame, alerts: pd.DataFrame, out_dir: str) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "events_csv": out / "events.csv",
        "alerts_csv": out / "alerts.csv",
        "alerts_json": out / "alerts.json",
        "sqlite": out / "logs.db",
    }
    events.to_csv(paths["events_csv"], index=False)
    alerts.to_csv(paths["alerts_csv"], index=False)
    with open(paths["alerts_json"], "w", encoding="utf-8") as f:
        json.dump(json.loads(alerts.to_json(orient="records", date_format="iso")), f, indent=2)

    # SQLite lets you query results with plain SQL, e.g.
    #   SELECT ip, COUNT(*) FROM events WHERE event='failed_password' GROUP BY ip;
    with sqlite3.connect(paths["sqlite"]) as conn:
        events.to_sql("events", conn, if_exists="replace", index=False)
        alerts.to_sql("alerts", conn, if_exists="replace", index=False)
    return {k: str(v) for k, v in paths.items()}


def summary(events: pd.DataFrame, alerts: pd.DataFrame, skipped: int) -> str:
    lines = [
        f"Parsed events : {len(events)}",
        f"Unparsed lines: {skipped}",
        f"Alerts        : {len(alerts)}",
    ]
    if not alerts.empty:
        lines.append("")
        lines.append("By severity:")
        for sev, n in alerts["severity"].value_counts().items():
            lines.append(f"  {sev:<9}{n}")
        lines.append("")
        lines.append("Top alerts:")
        for _, a in alerts.head(10).iterrows():
            who = next((v for v in (a["ip"], a["user"]) if isinstance(v, str) and v), "-")
            lines.append(f"  [{a['severity'].upper():<8}] {a['rule']:<24} {who:<16} {a['details']}")
    return "\n".join(lines)
