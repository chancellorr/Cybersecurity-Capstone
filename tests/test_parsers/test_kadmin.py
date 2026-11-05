
from kerbo_s.parsers.kadmin import classify_principal, parse_principal
from kerbo_s.parsers.kadmin import parse_policy


def test_TC_COL_01_classification():
    """TC-COL-01: Verify principal classification."""
    assert classify_principal("alice@KERBO.LAB") == "user"
    assert classify_principal("ben/admin@KERBO.LAB") == "admin"
    assert classify_principal("HTTP/web.kerbo.lab@KERBO.LAB") == "service"
    assert classify_principal("krbtgt/KERBO.LAB@KERBO.LAB") == "internal"


def test_TC_COL_01_principal_parsing():
    """TC-COL-01: Verify principal fields are parsed correctly."""
    sample = (
        "Principal: alice@KERBO.LAB\n"
        "Last password change: Mon Nov 02 18:05:11 UTC 2026\n"
        "Last successful authentication: [never]\n"
        "Policy: standard\n"
        "Key: vno 1, aes256-cts-hmac-sha1-96\n"
        "Key: vno 1, aes128-cts-hmac-sha1-96"
    )

    principal = parse_principal(sample)

    assert principal.name == "alice@KERBO.LAB"
    assert principal.kind == "user"
    assert principal.policy == "standard"
    assert principal.last_password_change.year == 2026
    assert principal.last_successful_auth is None
    assert principal.key_enctypes == (
        "aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96",
    )


def test_TC_COL_02_policy_parsing():
    """TC-COL-02: Verify Kerberos password policies are parsed."""
    sample = (
        "Policy: standard\n"
        "Maximum password life: 90 days 00:00:00\n"
        "Minimum password life: 0 days 00:00:00\n"
        "Minimum password length: 12\n"
        "Number of old keys kept: 1\n"
        "Maximum password failures before lockout: 0"
    )

    policy = parse_policy(sample)

    assert policy.name == "standard"
    assert policy.min_length == 12
    assert policy.max_life_days == 90
    assert policy.min_life_days == 0
    assert policy.history == 1
    assert policy.max_failures == 0


def test_TC_COL_07_malformed_principal():
    """TC-COL-07: Record malformed data without losing the principal."""
    sample = (
        "Principal: alice@KERBO.LAB\n"
        "BAD LINE\n"
        "Last password change: INVALID DATE\n"
        "Policy: standard"
    )

    errors = []
    principal = parse_principal(sample, errors)

    assert principal.name == "alice@KERBO.LAB"
    assert principal.policy == "standard"
    assert principal.last_password_change is None

    assert len(errors) == 2
    assert errors[0][0] == "getprinc"
    assert "Line 2" in errors[0][1]
    assert "Last password change" in errors[1][1]
