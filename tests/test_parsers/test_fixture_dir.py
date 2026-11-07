"""S2-06: load_fixture_dir on Ben's real lab fixtures (TC-COL-01, TC-COL-02, TC-COL-03, TC-COL-07)."""
import shutil
from pathlib import Path

from kerbo_s.parsers.kadmin import load_fixture_dir

REAL = Path("tests/fixtures/real")


def settings(snapshot):
    return {s.object_id: s.value for s in snapshot.config}


def test_tc_col_01_real_planted_principals_and_kinds():
    snapshot = load_fixture_dir(REAL / "planted")
    listed = (REAL / "planted" / "listprincs.txt").read_text(encoding="utf-8").split()
    kinds = {p.name: p.kind for p in snapshot.principals}
    assert len(snapshot.principals) == len(listed) == 14
    assert kinds["alice@KERBO.LAB"] == "user"
    assert kinds["ben/admin@KERBO.LAB"] == "admin"
    assert kinds["HTTP/web.kerbo.lab@KERBO.LAB"] == "service"
    assert kinds["krbtgt/KERBO.LAB@KERBO.LAB"] == "internal"


def test_tc_col_02_real_planted_policies():
    snapshot = load_fixture_dir(REAL / "planted")
    lengths = {p.name: p.min_length for p in snapshot.policies}
    assert lengths == {"standard": 12, "weakpol": 11}


def test_tc_col_03_fixture_dir_reads_krb5_conf_and_kdc_conf():
    found = settings(load_fixture_dir(REAL / "planted"))
    assert found["kdc.conf/realms/KERBO.LAB/max_life"] == "25h 0m 0s"
    assert found["kdc.conf/realms/KERBO.LAB/max_renewable_life"] == "8d 0h 0m 0s"
    assert "rc4-hmac:normal" in found["kdc.conf/realms/KERBO.LAB/supported_enctypes"]
    assert found["krb5.conf/libdefaults/allow_weak_crypto"] == "true"
    assert found["krb5.conf/libdefaults/default_realm"] == "KERBO.LAB"


def test_tc_col_03_real_fixture_dirs_load_without_errors():
    for name in ("clean", "planted", "aged"):
        snapshot = load_fixture_dir(REAL / name)
        assert snapshot.config, f"{name}: no config settings loaded"
        assert snapshot.errors == [], f"{name}: {snapshot.errors}"


def test_tc_col_07_missing_config_file_is_an_error_not_a_crash(tmp_path):
    folder = tmp_path / "clean"
    shutil.copytree(REAL / "clean", folder)
    (folder / "kdc.conf").unlink()

    snapshot = load_fixture_dir(folder)

    assert [source for source, _ in snapshot.errors] == ["kdc.conf"]
    assert any(s.file == "krb5.conf" for s in snapshot.config)
    assert not any(s.file == "kdc.conf" for s in snapshot.config)
    assert len(snapshot.principals) == 6


def test_tc_col_07_bad_config_line_is_an_error_not_a_crash(tmp_path):
    folder = tmp_path / "clean"
    shutil.copytree(REAL / "clean", folder)
    with open(folder / "kdc.conf", "a", encoding="utf-8") as handle:
        handle.write("this line is not a setting\n")

    snapshot = load_fixture_dir(folder)

    assert len(snapshot.errors) == 1
    assert snapshot.errors[0][0] == "kdc.conf"
    assert "kdc.conf/realms/KERBO.LAB/max_life" in settings(snapshot)
