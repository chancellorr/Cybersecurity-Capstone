"""Deterministic risk scoring. Severity comes only from the score (FR-RSK-01, FR-RSK-02)."""
from __future__ import annotations

from dataclasses import replace

from kerbo_s.models import Finding

WEIGHTS = {"impact": 0.40, "exploitability": 0.30, "exposure": 0.20, "compliance": 0.10}


def risk_score(factors: dict) -> float:
    return round(sum(factors[name] * weight for name, weight in WEIGHTS.items()), 1)


def severity_for(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score_finding(finding: Finding, config) -> Finding:
    factors = dict(config.factors(finding.rule_id))
    score = risk_score(factors)
    return replace(finding, score=score, severity=severity_for(score), factors=factors)
