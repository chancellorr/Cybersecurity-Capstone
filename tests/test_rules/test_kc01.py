from datetime import datetime, timedelta

from kerbo_s.config import Config
from kerbo_s.models import Principal, Snapshot
from kerbo_s.rules.kc01 import KC01PasswordAge

NOW = datetime(2026, 10, 29)
CONFIG = Config.load("config/rules.yaml")


def snapshot_with(*principals):
    return Snapshot(collected_at=NOW, principals=list(principals))


def user(name, age_days, kind="user"):
    return Principal(name=name, kind=kind, last_password_change=NOW - timedelta(days=age_days))


def test_flags_user_older_than_90_days():
    findings = list(KC01PasswordAge().evaluate(snapshot_with(user("a@X", 91)), CONFIG))
    assert [(f.object_id, f.observed, f.threshold) for f in findings] == [("a@X", 91, 90)]


def test_does_not_flag_user_at_exactly_90_days():
    assert list(KC01PasswordAge().evaluate(snapshot_with(user("a@X", 90)), CONFIG)) == []


def test_ignores_service_principals():
    findings = KC01PasswordAge().evaluate(snapshot_with(user("host/s@X", 400, kind="service")), CONFIG)
    assert list(findings) == []
