"""Runs rules over a Snapshot and scores the findings. No AI, no network, no clock."""
from __future__ import annotations

from kerbo_s.rules import ALL_RULES
from kerbo_s.scoring.scorer import score_finding


def run_audit(snapshot, config, rules=None):
    findings = []
    for rule in sorted(rules or ALL_RULES, key=lambda r: r.id):
        findings.extend(rule.evaluate(snapshot, config))
    scored = [score_finding(finding, config) for finding in findings]
    return sorted(scored, key=lambda f: (-f.score, f.rule_id, f.object_id))
