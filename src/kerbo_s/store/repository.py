"""SQLite storage for audit runs and their findings (FR-DB-01, FR-DB-02, Design Section 6.2).

Findings cannot be changed once saved: triggers in schema.sql reject any UPDATE or DELETE
on them (threat TM-05). Review status and notes live in the reviews table, which can change.
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml

from kerbo_s import RULESET_VERSION, __version__

SCHEMA = Path(__file__).with_name("schema.sql")
DEFAULT_DB = "audit_output/kerbo_s.db"


def database_path(app_config: str = "config/app.yaml") -> str:
    """The database file named by paths.database in config/app.yaml."""
    try:
        with open(app_config, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return DEFAULT_DB
    return (data.get("paths") or {}).get("database") or DEFAULT_DB


def open_db(path) -> sqlite3.Connection:
    """Connect, turn on foreign keys, and create any missing tables and triggers."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    return conn


def sha256_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_inputs(folder) -> list:
    """The files load_fixture_dir reads from a fixture folder (not the manifest or README)."""
    return [p for p in sorted(Path(folder).iterdir()) if p.is_file() and p.suffix in (".txt", ".conf")]


def _artifact_name(finding) -> str:
    """The input file a finding came from, so each stored finding points at its evidence."""
    if finding.object_type == "principal":
        return f"getprinc_{finding.object_id.replace('/', '_')}.txt"
    if finding.object_type == "policy":
        return f"getpol_{finding.object_id}.txt"
    if finding.object_type == "config":
        return finding.object_id.split("/", 1)[0]
    return ""


def _text(value):
    return None if value is None else str(value)


def save_audit(conn, findings, inputs, errors, mode, collected_at=None, config_hash=None) -> int:
    """Save one audit run in a single transaction and return its id.

    inputs: paths of the files the audit read (one artifacts row each, with its SHA-256).
    errors: the snapshot's collection errors as (source, message) pairs.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        audit_id = conn.execute(
            "INSERT INTO audits (started_at, mode, tool_version, ruleset_version, config_hash)"
            " VALUES (?, ?, ?, ?, ?)",
            (now, mode, __version__, RULESET_VERSION, config_hash),
        ).lastrowid

        artifact_ids = {}
        for path in inputs:
            path = Path(path)
            artifact_ids[path.name] = conn.execute(
                "INSERT INTO artifacts (audit_id, source, command_or_path, collected_at, sha256, stored_path)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (audit_id, path.name, str(path), _text(collected_at), sha256_file(path), None),
            ).lastrowid
        # A single input (a JSON snapshot) is the evidence for every finding.
        only = next(iter(artifact_ids.values())) if len(artifact_ids) == 1 else None

        for f in findings:
            factors = f.factors or {}
            conn.execute(
                "INSERT INTO findings (audit_id, rule_id, object_type, object_id, observed, threshold,"
                " impact, exploitability, exposure, compliance, score, severity, artifact_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (audit_id, f.rule_id, f.object_type, f.object_id, _text(f.observed), _text(f.threshold),
                 factors.get("impact"), factors.get("exploitability"), factors.get("exposure"),
                 factors.get("compliance"), f.score, f.severity,
                 artifact_ids.get(_artifact_name(f), only)),
            )

        for source, message in errors:
            conn.execute(
                "INSERT INTO collection_errors (audit_id, source, message, occurred_at) VALUES (?, ?, ?, ?)",
                (audit_id, source, message, now),
            )
    return audit_id


def list_findings(conn, audit_id) -> list:
    """One audit's findings as dicts, highest score first."""
    rows = conn.execute(
        "SELECT * FROM findings WHERE audit_id = ? ORDER BY score DESC, rule_id, object_id",
        (audit_id,),
    ).fetchall()
    return [dict(row) for row in rows]
