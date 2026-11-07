"""Headless mode (FR-UI-05): python -m kerbo_s.cli audit --snapshot FILE [--config FILE] [--db FILE]"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.snapshot.io import SnapshotError, load_snapshot
from kerbo_s.store.repository import database_path, open_db, save_audit, sha256_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kerbo-s")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="run an audit on a snapshot and print JSON findings")
    audit.add_argument("--snapshot", required=True)
    audit.add_argument("--config", default="config/rules.yaml")
    audit.add_argument("--db", help="SQLite file to save the audit in (default: paths.database in config/app.yaml)")
    args = parser.parse_args(argv)

    try:
        snapshot = load_snapshot(args.snapshot)
    except SnapshotError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    findings = run_audit(snapshot, Config.load(args.config))
    json.dump([asdict(f) for f in findings], sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")

    # S2-12: save every audit run with its findings, errors and input hashes (FR-DB-01).
    db = args.db or database_path()
    try:
        conn = open_db(db)
        try:
            save_audit(conn, findings, [args.snapshot], snapshot.errors, mode="snapshot",
                       collected_at=snapshot.collected_at, config_hash=sha256_file(args.config))
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        print(f"Error: could not save the audit to {db}: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
