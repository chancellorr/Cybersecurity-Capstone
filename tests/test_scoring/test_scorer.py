import pytest

from kerbo_s.config import Config
from kerbo_s.models import Finding
from kerbo_s.scoring.scorer import score_finding, severity_for

CONFIG = Config.load("config/rules.yaml")


@pytest.mark.parametrize("score,expected", [
    (24.9, "Low"), (25, "Medium"), (49.9, "Medium"),
    (50, "High"), (74.9, "High"), (75, "Critical"),
])
def test_severity_bands(score, expected):
    assert severity_for(score) == expected


@pytest.mark.parametrize("rule_id,score,severity", [
    ("KC-01", 38.5, "Medium"),
    ("KC-02", 70.0, "High"),
    ("KC-07", 88.5, "Critical"),
])
def test_baseline_scores_match_requirements(rule_id, score, severity):
    scored = score_finding(Finding(rule_id, "principal", "x", 1, 1), CONFIG)
    assert (scored.score, scored.severity) == (score, severity)
