"""S2-12: SQLite storage where saved findings cannot be changed (TC-DB-01, TC-DB-02)."""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from kerbo_s import cli
from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.models import Finding
from kerbo_s.parsers.kadmin import load_fixture_dir
from kerbo_s.store.repository import fixture_inputs, list_findings, open_db, save_audit

PLANTED = Path("tests/fixtures/real/planted")


def one_finding():
    factors = {"impact": 40, "exploitability": 35, "exposure": 30, "compliance": 60}
    return Finding("KC-01", "principal", "alice@KERBO.LAB", 120, 90, 38.5, "Medium", factors)


def test_tc_db_01_findings_are_immutable(tmp_path):
    conn = open_db(tmp_path / "test.db")
    audit_id = save_audit(conn, [one_finding()], [], [], mode="test")

    with pytest.raises(sqlite3.IntegrityError, match="findings are immutable"):
        conn.execute("UPDATE findings SET score = 0")
    with pytest.raises(sqlite3.IntegrityError, match="findings are immutable"):
        conn.execute("DELETE FROM findings")

    stored = list_findings(conn, audit_id)
    assert len(stored) == 1 and stored[0]["score"] == 38.5


def test_tc_db_01_review_notes_can_change(tmp_path):
    conn = open_db(tmp_path / "test.db")
    audit_id = save_audit(conn, [one_finding()], [], [], mode="test")
    finding_id = list_findings(conn, audit_id)[0]["id"]

    conn.execute("INSERT INTO reviews (finding_id, status, note) VALUES (?, 'open', 'first look')", (finding_id,))
    conn.execute("UPDATE reviews SET status = 'reviewed', note = 'accepted risk' WHERE finding_id = ?", (finding_id,))

    assert tuple(conn.execute("SELECT status, note FROM reviews").fetchone()) == ("reviewed", "accepted risk")


def test_tc_db_02_fixture_audit_reads_back_with_artifact_hash(tmp_path):
    snapshot = load_fixture_dir(PLANTED)
    findings = run_audit(snapshot, Config.load("config/rules.yaml"))
    inputs = fixture_inputs(PLANTED)
    conn = open_db(tmp_path / "test.db")
    audit_id = save_audit(conn, findings, inputs, snapshot.errors, mode="fixture",
                          collected_at=snapshot.collected_at)

    stored = list_findings(conn, audit_id)
    assert len(stored) == len(findings) > 0
    scores = [row["score"] for row in stored]
    assert scores == sorted(scores, reverse=True)

    carol = next(row for row in stored if row["object_id"] == "carol@KERBO.LAB")
    assert (carol["rule_id"], carol["object_type"], carol["observed"], carol["threshold"]) == (
        "KC-03", "principal", "no policy", "12")

    audit = conn.execute("SELECT started_at, mode FROM audits WHERE id = ?", (audit_id,)).fetchone()
    assert audit["started_at"] and audit["mode"] == "fixture"

    artifact = conn.execute("SELECT * FROM artifacts WHERE id = ?", (carol["artifact_id"],)).fetchone()
    assert artifact["source"] == "getprinc_carol@KERBO.LAB.txt"
    assert len(artifact["sha256"]) == 64
    assert artifact["sha256"] == hashlib.sha256((PLANTED / artifact["source"]).read_bytes()).hexdigest()
    assert conn.execute("SELECT COUNT(*) FROM artifacts WHERE audit_id = ?", (audit_id,)).fetchone()[0] == len(inputs)


def test_tc_db_02_cli_saves_each_audit(tmp_path, capsys):
    db = tmp_path / "cli.db"
    assert cli.main(["audit", "--snapshot", "tests/fixtures/sample_snapshot.json", "--db", str(db)]) == 0
    printed = json.loads(capsys.readouterr().out)

    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == len(printed)
    sha256, source = conn.execute("SELECT sha256, source FROM artifacts").fetchone()
    assert source == "sample_snapshot.json" and len(sha256) == 64
