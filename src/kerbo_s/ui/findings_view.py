"""Pure logic behind the findings table (FR-UI-02), kept out of Qt so it can be unit-tested."""
from __future__ import annotations

CATEGORY = {
    "KC-01": "Credentials", "KC-02": "Credentials", "KC-03": "Credentials",
    "KC-04": "Principals", "KC-05": "Principals", "KC-06": "Principals",
    "KC-07": "Configuration", "KC-08": "Configuration", "KC-09": "Configuration",
    "KC-10": "Authentication", "KC-11": "Authentication",
}
SEVERITIES = ("Critical", "High", "Medium", "Low")
SEVERITY_FILTER = ("All",) + SEVERITIES
CATEGORY_FILTER = ("All", "Credentials", "Principals", "Configuration")
HEADERS = ["Severity", "Score", "Rule", "Category", "Object", "Observed", "Threshold", "Status"]


def filter_findings(findings, severity="All", category="All"):
    """Keep the engine's order (highest score first) and apply both filters."""
    return [
        f for f in findings
        if (severity == "All" or f.severity == severity)
        and (category == "All" or CATEGORY.get(f.rule_id) == category)
    ]


def severity_counts(findings) -> dict:
    return {s: sum(f.severity == s for f in findings) for s in SEVERITIES}


def counts_text(findings) -> str:
    return " · ".join(f"{s} {n}" for s, n in severity_counts(findings).items())


def row_values(finding) -> list:
    """Status is "New" for every finding in Sprint 2; review status is Sprint 3 (FR-UI-04)."""
    return [finding.severity, finding.score, finding.rule_id, CATEGORY.get(finding.rule_id, ""),
            finding.object_id, finding.observed, finding.threshold, "New"]
