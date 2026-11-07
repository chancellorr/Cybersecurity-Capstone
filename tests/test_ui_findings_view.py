"""TC-UI-02: the findings table's filters and counts (the logic the window uses)."""
from kerbo_s.models import Finding
from kerbo_s.ui.findings_view import CATEGORY, counts_text, filter_findings, row_values, severity_counts

FINDINGS = [  # already sorted by score, as run_audit returns them
    Finding("KC-07", "config", "kdc.conf/realms/KERBO.LAB/supported_enctypes", "rc4-hmac", "no RC4", 88.5, "Critical"),
    Finding("KC-02", "principal", "host/web.kerbo.lab@KERBO.LAB", 400, 180, 70.0, "High"),
    Finding("KC-06", "principal", "eve/admin@KERBO.LAB", "admin", "listed", 68.0, "High"),
    Finding("KC-01", "principal", "alice@KERBO.LAB", 120, 90, 38.5, "Medium"),
]


def test_tc_ui_02_severity_filter():
    assert [f.rule_id for f in filter_findings(FINDINGS, severity="High")] == ["KC-02", "KC-06"]


def test_tc_ui_02_category_filter():
    assert [f.rule_id for f in filter_findings(FINDINGS, category="Credentials")] == ["KC-02", "KC-01"]


def test_tc_ui_02_both_filters_and_all():
    assert [f.rule_id for f in filter_findings(FINDINGS, "High", "Principals")] == ["KC-06"]
    assert filter_findings(FINDINGS) == FINDINGS


def test_tc_ui_02_counts_line():
    assert severity_counts(FINDINGS) == {"Critical": 1, "High": 2, "Medium": 1, "Low": 0}
    assert counts_text(FINDINGS) == "Critical 1 · High 2 · Medium 1 · Low 0"


def test_tc_ui_02_row_has_category_and_status():
    assert row_values(FINDINGS[0])[2:4] == ["KC-07", "Configuration"]
    assert row_values(FINDINGS[0])[-1] == "New"
    assert all(CATEGORY[f"KC-{n:02d}"] for n in range(1, 12))
