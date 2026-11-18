"""S3-04: the live collector runs only allow-listed, read-only commands (TC-COL-06, NFR-SEC-01).

No KDC is needed: a fake runner answers kadmin.local and journalctl with real output copied
from tests/fixtures/real/planted, and the config files are read from that folder.
"""
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from kerbo_s.collectors.live import (
    JOURNAL, CollectionError, Collector, NotAllowed, included_name, is_allowed, main,
)
from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.parsers.kadmin import load_fixture_dir
from kerbo_s.snapshot.hashing import MISMATCH, VERIFIED, verify_hashes
from kerbo_s.snapshot.io import import_snapshot

PLANTED = Path("tests/fixtures/real/planted")
NOW = datetime.fromisoformat((PLANTED / "collected_at.txt").read_text().strip())
LOG = ("2026-11-07T04:40:01-0600 kdc krb5kdc[812]: AS_REQ (4 etypes {18 17 20 19}) 10.27.27.32: "
       "ISSUE: authtime 1794040801, etypes {rep=18 tkt=18 ses=18}, alice@KERBO.LAB for krbtgt/KERBO.LAB@KERBO.LAB\n")


class FakeKDC:
    """Answers allow-listed commands from the planted fixture and records every call."""

    def __init__(self, fail_on=None, missing_program=False):
        self.calls = []
        self.fail_on = fail_on
        self.missing_program = missing_program

    def __call__(self, argv, **kwargs):
        assert kwargs["shell"] is False and kwargs["timeout"] == 30
        self.calls.append(list(argv))
        if self.missing_program:
            raise FileNotFoundError(2, "No such file or directory", argv[0])
        if argv[0] == "journalctl":
            return subprocess.CompletedProcess(argv, 0, LOG.encode(), b"")
        query = argv[2]
        if query == self.fail_on:
            return subprocess.CompletedProcess(argv, 1, b"", b"kadmin.local: Cannot contact any KDC")
        if query == "listprincs":
            text = (PLANTED / "listprincs.txt").read_text()
        elif query == "getpols":
            text = (PLANTED / "getpols.txt").read_text()
        else:
            kind, name = query.split(" ")
            prefix = "getprinc_" if kind == "getprinc" else "getpol_"
            text = (PLANTED / f"{prefix}{name.replace('/', '_')}.txt").read_text()
        return subprocess.CompletedProcess(argv, 0, ("Authenticating as principal root/admin@KERBO.LAB with password.\n" + text).encode(), b"")


def collector(tmp_path, runner, **kwargs):
    """A collector whose config files are the planted ones. The lab krb5.conf has
    'includedir /etc/krb5.conf.d/', which only exists on the KDC, so the copy used here
    points it at an empty folder in tmp_path instead."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    conf_d = tmp_path / "krb5.conf.d"
    conf_d.mkdir(exist_ok=True)
    krb5 = tmp_path / "krb5.conf"
    krb5.write_text((PLANTED / "krb5.conf").read_text().replace("/etc/krb5.conf.d/", f"{conf_d}/"))
    files = {str(krb5): "krb5.conf", str(PLANTED / "kdc.conf"): "kdc.conf"}
    return Collector(tmp_path / "snap", runner=runner, now=NOW, config_files=files, optional_files={}, **kwargs)


@pytest.mark.parametrize("argv", [
    ["kadmin.local", "-q", "delprinc alice"],
    ["kadmin.local", "-q", "addprinc -pw x mallory"],
    ["kadmin.local", "-q", "cpw alice"],
    ["kadmin.local", "-q", "getprinc alice; delprinc alice"],
    ["kadmin.local", "-q", "getprinc alice bob"],
    ["kadmin.local", "-q", "getprinc $(reboot)"],
    ["kadmin.local", "-q", "listprincs", "-x"],
    ["kadmin", "-q", "listprincs"],
    ["bash", "-c", "kadmin.local -q listprincs"],
    JOURNAL + ["yesterday; rm -rf /"],
    ["journalctl", "--rotate"],
])
def test_tc_col_06_commands_off_the_list_never_run(tmp_path, argv):
    fake = FakeKDC()
    c = collector(tmp_path, fake)
    c.out.mkdir()
    with pytest.raises(NotAllowed):
        c.run_allowed(argv)
    assert fake.calls == []


def test_tc_col_06_allowed_shapes():
    assert is_allowed(["kadmin.local", "-q", "listprincs"])
    assert is_allowed(["kadmin.local", "-q", "getprinc HTTP/web.kerbo.lab@KERBO.LAB"])
    assert is_allowed(["kadmin.local", "-q", "getpol standard"])
    assert is_allowed(JOURNAL + ["2026-10-08"])


def test_tc_col_06_commands_log_lists_every_command_and_only_reads(tmp_path):
    fake = FakeKDC()
    c = collector(tmp_path, fake)
    assert c.collect() == []
    lines = (c.out / "commands.log").read_text().splitlines()
    commands = [line.split(" ", 2)[2] for line in lines if " exit=" in line]
    assert len(commands) == len(fake.calls)
    for line in lines:
        status, command = line.split(" ", 2)[1:]
        assert status == "exit=0" or status == "read", line
        assert (command.startswith(("kadmin.local -q listprincs", "kadmin.local -q getprinc ",
                                    "kadmin.local -q getpols", "kadmin.local -q getpol ", "journalctl "))
                or status == "read"), line


def test_tc_col_08_collected_folder_audits_like_the_fixture(tmp_path):
    c = collector(tmp_path, FakeKDC())
    c.collect()
    snapshot = import_snapshot(c.out)
    assert snapshot.integrity == VERIFIED and snapshot.errors == []
    rules = Config.load("config/rules.yaml")
    got = [(f.rule_id, f.object_id) for f in run_audit(snapshot, rules)]
    want = [(f.rule_id, f.object_id) for f in run_audit(load_fixture_dir(PLANTED), rules)]
    assert got == want and got
    assert (c.out / "krb5kdc.log").read_text() == LOG
    assert "Authenticating" not in (c.out / "listprincs.txt").read_text()


def test_tc_col_09_collected_folder_detects_later_change(tmp_path):
    c = collector(tmp_path, FakeKDC())
    c.collect()
    (c.out / "getpol_weakpol.txt").write_text("Policy: weakpol\nMinimum password length: 20\n")
    assert verify_hashes(c.out)[0] == MISMATCH


def test_tc_ui_04_unreachable_kdc_raises_collection_error(tmp_path):
    with pytest.raises(CollectionError, match="Cannot reach the KDC"):
        collector(tmp_path, FakeKDC(fail_on="listprincs")).collect()
    with pytest.raises(CollectionError, match="kadmin.local not found"):
        collector(tmp_path / "b", FakeKDC(missing_program=True)).collect()


def test_tc_col_07_one_failed_command_is_recorded_and_the_rest_continues(tmp_path):
    c = collector(tmp_path, FakeKDC(fail_on="getpol weakpol"))
    errors = c.collect()
    assert [source for source, _ in errors] == ["getpol_weakpol.txt"]
    assert (c.out / "getpol_standard.txt").exists() and not (c.out / "getpol_weakpol.txt").exists()
    assert "getpol_weakpol.txt" in (c.out / "collection_errors.txt").read_text()
    snapshot = import_snapshot(c.out)
    assert snapshot.integrity == VERIFIED
    assert any(source == "getpol_weakpol.txt" for source, _ in snapshot.errors)


def test_includedir_files_are_copied_and_hashed(tmp_path):
    conf_d = tmp_path / "krb5.conf.d"
    conf_d.mkdir()
    (conf_d / "crypto.conf").write_text("[libdefaults]\n    allow_weak_crypto = true\n")
    (conf_d / "notes.txt~").write_text("editor backup, not read by MIT\n")
    main_conf = tmp_path / "krb5.conf"
    main_conf.write_text(f"includedir {conf_d}/\n[libdefaults]\n    default_realm = KERBO.LAB\n")
    c = Collector(tmp_path / "snap", runner=FakeKDC(), now=NOW, config_files={str(main_conf): "krb5.conf"},
                  optional_files={})
    c.collect()
    copied = c.out / included_name(conf_d / "crypto.conf")
    assert copied.read_text().endswith("allow_weak_crypto = true\n")
    assert not (c.out / included_name(conf_d / "notes.txt~")).exists()
    assert verify_hashes(c.out)[0] == VERIFIED


def test_include_loop_is_stopped(tmp_path):
    a, b = tmp_path / "a.conf", tmp_path / "b.conf"
    a.write_text(f"include {b}\n")
    b.write_text(f"include {a}\n")
    c = Collector(tmp_path / "snap", runner=FakeKDC(), now=NOW, config_files={str(a): "krb5.conf"}, optional_files={})
    errors = c.collect()
    assert any("include loop" in message for _, message in errors)


def test_output_folder_must_be_new(tmp_path):
    out = tmp_path / "snap"
    out.mkdir()
    (out / "old.txt").write_text("x")
    with pytest.raises(CollectionError, match="not empty"):
        Collector(out, runner=FakeKDC(), now=NOW).collect()


def test_main_reports_unreachable_kdc_without_traceback(tmp_path, monkeypatch, capsys):
    import kerbo_s.collectors.live as live
    real = live.Collector
    monkeypatch.setattr(live, "Collector",
                        lambda out, since_days: real(out, runner=FakeKDC(missing_program=True), now=NOW))
    assert main(["--out", str(tmp_path / "snap")]) == 2
    err = capsys.readouterr().err
    assert "Cannot reach the KDC" in err and "Traceback" not in err


def test_missing_includedir_is_recorded_not_fatal(tmp_path):
    conf = tmp_path / "krb5.conf"
    conf.write_text(f"includedir {tmp_path / 'does-not-exist'}/\n[libdefaults]\n    default_realm = KERBO.LAB\n")
    c = Collector(tmp_path / "snap", runner=FakeKDC(), now=NOW, config_files={str(conf): "krb5.conf"}, optional_files={})
    errors = c.collect()
    assert any("includedir cannot be read" in message for _, message in errors)
    assert (c.out / "krb5.conf").exists() and (c.out / "hashes.json").exists()
