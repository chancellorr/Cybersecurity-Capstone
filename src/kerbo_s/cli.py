"""Headless mode (FR-UI-05): python -m kerbo_s.cli audit --snapshot FILE_OR_FOLDER [--config FILE] [--db FILE]

--snapshot takes a JSON snapshot file, a snapshot folder (hashes checked) or a fixture folder.

Exit codes: 0 audit saved; 2 snapshot missing or unreadable; 3 audit could not be saved;
4 snapshot folder failed its hash check (the audit is still saved, flagged 'mismatch').
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.snapshot.io import SnapshotError, load_snapshot
from kerbo_s.snapshot.hashing import MISMATCH
from kerbo_s.store.repository import database_path, fixture_inputs, open_db, save_audit, sha256_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kerbo-s")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="run an audit on a snapshot and print JSON findings")
    audit.add_argument("--snapshot", required=True, help="JSON snapshot file, snapshot folder or fixture folder")
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
    is_folder = Path(args.snapshot).is_dir()
    inputs = fixture_inputs(args.snapshot) if is_folder else [args.snapshot]
    db = args.db or database_path()
    try:
        conn = open_db(db)
        try:
            save_audit(conn, findings, inputs, snapshot.errors, mode="folder" if is_folder else "snapshot",
                       collected_at=snapshot.collected_at, config_hash=sha256_file(args.config),
                       integrity=snapshot.integrity)
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        print(f"Error: could not save the audit to {db}: {exc}", file=sys.stderr)
        return 3

    # S3-05: a changed, missing or added file is reported, and the saved audit is flagged (TC-COL-09).
    if snapshot.integrity == MISMATCH:
        print("Warning: the snapshot failed its hash check; the audit was saved and flagged 'mismatch':",
              file=sys.stderr)
        for source, message in snapshot.errors:
            if message.startswith("hash mismatch") or source == "hashes.json":
                print(f"  {source}: {message}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
