"""S2-22: end-to-end tests against the lab's ground truth (TC-KC-12, TC-KC-15).

These run the real pipeline (load_fixture_dir, then run_audit) on Ben's real KDC fixtures
and compare the findings to the expected_findings.yaml manifest in each folder.
A finding matches when rule_id and object_id match.
"""
from pathlib import Path

import pytest
import yaml

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.parsers.kadmin import load_fixture_dir

REAL = Path("tests/fixtures/real")
CONFIG = Config.load("config/rules.yaml")
# KC-06 reads the lab's own justification list, which lists ben/admin (not eve/admin).
CONFIG.data["rules"]["KC-06"]["thresholds"]["justification_file"] = str(REAL / "admin_justifications.yaml")


def manifest(folder):
    return yaml.safe_load((folder / "expected_findings.yaml").read_text(encoding="utf-8"))


def keys(findings):
    return {(f.rule_id, f.object_id) for f in findings}


def test_tc_kc_12_clean_realm_zero_findings_and_repeatable():
    first = run_audit(load_fixture_dir(REAL / "clean"), CONFIG)
    second = run_audit(load_fixture_dir(REAL / "clean"), CONFIG)
    assert first == [], f"Unexpected findings on the clean realm: {sorted(keys(first))}"
    assert first == second


@pytest.mark.parametrize("name", ["planted", "aged"])
def test_tc_kc_15_findings_match_manifest(name):
    folder = REAL / name
    m = manifest(folder)
    found = keys(run_audit(load_fixture_dir(folder), CONFIG))
    expected = {(e["rule_id"], e["object_id"]) for e in m["expected"]}
    forbidden = {(e["rule_id"], e["object_id"]) for e in m.get("not_expected", [])}
    assert not (expected - found), f"Missed (false negatives): {sorted(expected - found)}"
    assert not (found & forbidden), f"Boundary cases flagged: {sorted(found & forbidden)}"
    assert not (found - expected), f"Extra findings (false positives): {sorted(found - expected)}"
