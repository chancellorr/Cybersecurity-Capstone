"""S3-05: snapshot folders are hashed at capture and checked on import (FR-COL-08, FR-COL-09, NFR-SEC-02).

TC-COL-08: export a snapshot, import it, and the findings match a direct audit of the same data.
TC-COL-09 (TV-14): change one raw file after export; the import reports it and the audit is flagged.
"""
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from kerbo_s import cli
from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.parsers.kadmin import load_fixture_dir
from kerbo_s.snapshot.hashing import MISMATCH, NOT_HASHED, VERIFIED, verify_hashes
from kerbo_s.snapshot.io import SnapshotError, export_snapshot, import_snapshot

PLANTED = Path("tests/fixtures/real/planted")
RULES = Config.load("config/rules.yaml")


def keys(findings):
    return [(f.rule_id, f.object_id, f.score) for f in findings]


@pytest.fixture
def exported(tmp_path):
    return export_snapshot(load_fixture_dir(PLANTED), PLANTED, tmp_path / "snapshot")


def test_tc_col_08_export_then_import_gives_same_findings(exported):
    direct = run_audit(load_fixture_dir(PLANTED), RULES)
    imported = import_snapshot(exported)
    assert imported.integrity == VERIFIED
    assert imported.errors == []
    assert keys(run_audit(imported, RULES)) == keys(direct)
    assert len(direct) > 0


def test_tc_col_08_folder_holds_raw_files_snapshot_json_and_hashes(exported):
    names = {p.name for p in exported.iterdir()}
    assert {"hashes.json", "snapshot.json", "collected_at.txt", "listprincs.txt", "kdc.conf"} <= names
    assert "expected_findings.yaml" not in names  # the manifest is ground truth, not KDC data
    data = json.loads((exported / "snapshot.json").read_text(encoding="utf-8"))
    assert {"principals", "policies", "config", "errors", "collected_at"} <= set(data)
    assert len(data["principals"]) > 0 and len(data["policies"]) > 0 and len(data["config"]) > 0
    hashes = json.loads((exported / "hashes.json").read_text(encoding="utf-8"))
    assert hashes["algorithm"] == "sha256"
    assert "snapshot.json" in hashes["files"] and "hashes.json" not in hashes["files"]


def test_tc_col_09_changed_file_is_reported_and_flagged(exported):
    kdc = exported / "kdc.conf"
    kdc.write_bytes(kdc.read_bytes().replace(b"max_life = 25h", b"max_life = 10h"))
    snapshot = import_snapshot(exported)
    assert snapshot.integrity == MISMATCH
    assert ("kdc.conf", "hash mismatch: file changed after capture") in snapshot.errors


def test_tc_col_09_missing_and_added_files_are_reported(exported):
    (exported / "getpols.txt").unlink()
    (exported / "extra.txt").write_text("not captured\n", encoding="utf-8")
    status, problems = verify_hashes(exported)
    assert status == MISMATCH
    assert ("getpols.txt", "hash mismatch: file listed in hashes.json is missing") in problems
    assert ("extra.txt", "hash mismatch: file added after capture") in problems


def test_tc_col_09_cli_exits_4_and_saves_flagged_audit(exported, tmp_path, capsys):
    (exported / "krb5.conf").write_text("[libdefaults]\n    allow_weak_crypto = false\n", encoding="utf-8")
    db = tmp_path / "audit.db"
    assert cli.main(["audit", "--snapshot", str(exported), "--db", str(db)]) == 4
    err = capsys.readouterr().err
    assert "krb5.conf: hash mismatch: file changed after capture" in err and "Traceback" not in err
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT mode, integrity FROM audits").fetchall() == [("folder", "mismatch")]


def test_verified_folder_cli_exits_0(exported, tmp_path):
    db = tmp_path / "audit.db"
    assert cli.main(["audit", "--snapshot", str(exported), "--db", str(db)]) == 0
    assert sqlite3.connect(db).execute("SELECT integrity FROM audits").fetchone() == ("verified",)


def test_sprint2_fixture_folder_loads_as_not_hashed(tmp_path):
    snapshot = import_snapshot(PLANTED)
    assert snapshot.integrity == NOT_HASHED and snapshot.errors == []
    db = tmp_path / "audit.db"
    assert cli.main(["audit", "--snapshot", str(PLANTED), "--db", str(db)]) == 0


def test_export_refuses_a_folder_that_is_not_empty(tmp_path):
    out = tmp_path / "used"
    out.mkdir()
    (out / "old.txt").write_text("x", encoding="utf-8")
    with pytest.raises(SnapshotError, match="not empty"):
        export_snapshot(load_fixture_dir(PLANTED), PLANTED, out)


def test_old_database_gets_integrity_column(tmp_path):
    from kerbo_s.store.repository import open_db
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE audits (id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, mode TEXT NOT NULL,"
                " tool_version TEXT NOT NULL, ruleset_version TEXT NOT NULL, config_hash TEXT)")
    old.commit()
    old.close()
    columns = {row["name"] for row in open_db(path).execute("PRAGMA table_info(audits)")}
    assert "integrity" in columns


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions")
def test_tc_sec_01_snapshot_folder_700_files_600(exported):
    assert stat.S_IMODE(exported.stat().st_mode) == 0o700
    for path in exported.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
