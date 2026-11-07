"""TC-UI-06: a missing, invalid or incomplete snapshot gives a clear message and exit code 2, not a crash."""
import json

from kerbo_s import cli


def run(path):
    return cli.main(["audit", "--snapshot", str(path)])


def test_tc_ui_06_missing_file(tmp_path, capsys):
    assert run(tmp_path / "nothing.json") == 2
    err = capsys.readouterr().err
    assert "Snapshot file not found" in err and "Traceback" not in err


def test_tc_ui_06_invalid_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert run(path) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_tc_ui_06_missing_fields(tmp_path, capsys):
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps({"principals": []}), encoding="utf-8")
    assert run(path) == 2
    assert "missing required fields: collected_at" in capsys.readouterr().err


def test_tc_ui_06_principal_missing_kind(tmp_path, capsys):
    path = tmp_path / "bad_principal.json"
    path.write_text(json.dumps({"collected_at": "2026-11-05T00:00:00", "principals": [{"name": "alice@KERBO.LAB"}]}), encoding="utf-8")
    assert run(path) == 2
    assert "Principal entry 1 is missing the field 'kind'" in capsys.readouterr().err


def test_tc_ui_06_valid_snapshot_still_works(capsys):
    assert run("tests/fixtures/sample_snapshot.json") == 0
    assert "KC-02" in capsys.readouterr().out
