"""Command-line entry point.

Examples:
    python -m log_pipeline.cli --input data/sample_auth.log --format auth
    python -m log_pipeline.cli --input data/sample_access.log --format access --out output/web
"""

import argparse
import sys

import yaml

from log_pipeline.detectors import run_detectors
from log_pipeline.parsers import parse_file
from log_pipeline.report import summary, write_outputs


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Parse logs and flag anomalies.")
    p.add_argument("--input", required=True, help="Path to the log file")
    p.add_argument("--format", choices=["auth", "access"], required=True)
    p.add_argument("--out", default="output", help="Output directory")
    p.add_argument("--config", default="config/rules.yaml", help="Detector thresholds")
    p.add_argument("--year", type=int, help="Year for auth logs (syslog lines omit it)")
    args = p.parse_args(argv)

    try:
        with open(args.config, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        config = {}

    events, skipped = parse_file(args.input, args.format, args.year)
    alerts = run_detectors(events, args.format, config.get(args.format, {}))
    paths = write_outputs(events, alerts, args.out)

    print(summary(events, alerts, skipped))
    print(f"\nOutputs written to {args.out}/ ({', '.join(p.split('/')[-1] for p in paths.values())})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
