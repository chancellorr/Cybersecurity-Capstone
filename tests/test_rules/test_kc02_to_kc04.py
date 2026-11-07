from datetime import datetime, timedelta

from kerbo_s.config import Config
from kerbo_s.models import Policy, Principal, Snapshot
from kerbo_s.rules.kc02 import KC02ServicePasswordAge
from kerbo_s.rules.kc03 import KC03WeakPasswordPolicy
from kerbo_s.rules.kc04 import KC04InactiveUser

NOW = datetime(2026, 11, 5)
CONFIG = Config.load("config/rules.yaml")


def ago(days):
    return NOW - timedelta(days=days)


def findings(rule, principals=(), policies=()):
    snap = Snapshot(collected_at=NOW, principals=list(principals), policies=list(policies))
    return [(f.object_type, f.object_id) for f in rule.evaluate(snap, CONFIG)]


# TC-KC-02: service principal password older than 180 days
def test_tc_kc_02_service_181_days_flagged():
    p = Principal("host/web.kerbo.lab@KERBO.LAB", "service", last_password_change=ago(181))
    assert findings(KC02ServicePasswordAge(), [p]) == [("principal", "host/web.kerbo.lab@KERBO.LAB")]


def test_tc_kc_02_service_180_days_not_flagged():
    p = Principal("host/web.kerbo.lab@KERBO.LAB", "service", last_password_change=ago(180))
    assert findings(KC02ServicePasswordAge(), [p]) == []


def test_tc_kc_02_user_181_days_not_flagged():
    p = Principal("alice@KERBO.LAB", "user", last_password_change=ago(181))
    assert findings(KC02ServicePasswordAge(), [p]) == []


# TC-KC-03: weak policy (min length under 12) or principal with no policy
def test_tc_kc_03_policy_length_11_flagged_12_not():
    pols = [Policy("weakpol", min_length=11), Policy("standard", min_length=12)]
    assert findings(KC03WeakPasswordPolicy(), policies=pols) == [("policy", "weakpol")]


def test_tc_kc_03_user_without_policy_flagged():
    p = Principal("carol@KERBO.LAB", "user", policy=None)
    assert findings(KC03WeakPasswordPolicy(), [p]) == [("principal", "carol@KERBO.LAB")]


def test_tc_kc_03_internal_principal_without_policy_not_flagged():
    internal = [Principal("K/M@KERBO.LAB", "internal"), Principal("krbtgt/KERBO.LAB@KERBO.LAB", "internal")]
    assert findings(KC03WeakPasswordPolicy(), internal) == []


def test_tc_kc_03_principal_with_policy_not_flagged():
    p = Principal("alice@KERBO.LAB", "user", policy="standard")
    assert findings(KC03WeakPasswordPolicy(), [p]) == []


# TC-KC-04: user inactive more than 180 days
def test_tc_kc_04_user_181_days_flagged_179_not():
    users = [Principal("old@KERBO.LAB", "user", last_successful_auth=ago(181)),
             Principal("recent@KERBO.LAB", "user", last_successful_auth=ago(179))]
    assert findings(KC04InactiveUser(), users) == [("principal", "old@KERBO.LAB")]


def test_tc_kc_04_user_exactly_180_days_not_flagged():
    p = Principal("edge@KERBO.LAB", "user", last_successful_auth=ago(180))
    assert findings(KC04InactiveUser(), [p]) == []


def test_tc_kc_04_never_authenticated_uses_password_date():
    p = Principal("dave@KERBO.LAB", "user", last_successful_auth=None, last_password_change=ago(200))
    assert findings(KC04InactiveUser(), [p]) == [("principal", "dave@KERBO.LAB")]


def test_tc_kc_04_service_principal_not_checked():
    p = Principal("host/web.kerbo.lab@KERBO.LAB", "service", last_successful_auth=ago(400))
    assert findings(KC04InactiveUser(), [p]) == []
