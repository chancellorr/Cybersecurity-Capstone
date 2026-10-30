"""Headless mode (FR-UI-05): python -m kerbo_s.cli audit --snapshot FILE [--config FILE]"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.snapshot.io import load_snapshot


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kerbo-s")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="run an audit on a snapshot and print JSON findings")
    audit.add_argument("--snapshot", required=True)
    audit.add_argument("--config", default="config/rules.yaml")
    args = parser.parse_args(argv)

    findings = run_audit(load_snapshot(args.snapshot), Config.load(args.config))
    json.dump([asdict(f) for f in findings], sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
