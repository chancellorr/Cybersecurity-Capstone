from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.snapshot.io import load_snapshot


def test_sample_snapshot_gives_one_scored_finding():
    findings = run_audit(load_snapshot("tests/fixtures/sample_snapshot.json"), Config.load("config/rules.yaml"))
    assert [(f.rule_id, f.object_id, f.severity) for f in findings] == [("KC-01", "alice@LAB.LOCAL", "Medium")]


def test_audit_is_deterministic():
    snap = load_snapshot("tests/fixtures/sample_snapshot.json")
    cfg = Config.load("config/rules.yaml")
    assert run_audit(snap, cfg) == run_audit(snap, cfg)
