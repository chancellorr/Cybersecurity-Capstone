from datetime import datetime

import yaml

from kerbo_s.config import Config
from kerbo_s.models import ConfigSetting, Finding, Principal, Snapshot
from kerbo_s.rules.kc06 import KC06UnjustifiedAdmin
from kerbo_s.rules.kc07 import KC07WeakEncryption
from kerbo_s.rules.kc08 import KC08TicketLifetime
from kerbo_s.rules.kc09 import KC09RenewableLifetime
from kerbo_s.scoring.scorer import score_finding

NOW = datetime(2026, 11, 4)
CONFIG = Config.load("config/rules.yaml")


def snap(principals=(), config=()):
    return Snapshot(collected_at=NOW, principals=list(principals), config=list(config))


def ids(rule, snapshot, config=CONFIG):
    return [f.object_id for f in rule.evaluate(snapshot, config)]


def test_tc_kc_06_unlisted_admin_flagged_listed_admin_not(tmp_path):
    path = tmp_path / "just.yaml"
    path.write_text(yaml.safe_dump({"approved_admins": [{"principal": "ben/admin@KERBO.LAB", "justification": "lab admin"}]}))
    cfg = Config.load("config/rules.yaml")
    cfg.data["rules"]["KC-06"]["thresholds"]["justification_file"] = str(path)
    s = snap([Principal("ben/admin@KERBO.LAB", "admin"), Principal("eve/admin@KERBO.LAB", "admin"), Principal("alice@KERBO.LAB", "user")])
    assert ids(KC06UnjustifiedAdmin(), s, cfg) == ["eve/admin@KERBO.LAB"]


def test_tc_kc_06_missing_justification_file_flags_every_admin(tmp_path):
    cfg = Config.load("config/rules.yaml")
    cfg.data["rules"]["KC-06"]["thresholds"]["justification_file"] = str(tmp_path / "missing.yaml")
    s = snap([Principal("ben/admin@KERBO.LAB", "admin")])
    assert ids(KC06UnjustifiedAdmin(), s, cfg) == ["ben/admin@KERBO.LAB"]


def test_tc_kc_07_weak_settings_and_keys_flagged_aes_only_not():
    s = snap(
        [Principal("host/legacy.kerbo.lab@KERBO.LAB", "service", key_enctypes=("arcfour-hmac",)),
         Principal("alice@KERBO.LAB", "user", key_enctypes=("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"))],
        [ConfigSetting("kdc.conf", "realms/KERBO.LAB", "supported_enctypes", "aes256-cts-hmac-sha1-96:normal rc4-hmac:normal"),
         ConfigSetting("krb5.conf", "libdefaults", "allow_weak_crypto", "true"),
         ConfigSetting("krb5.conf", "libdefaults", "permitted_enctypes", "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96")])
    assert ids(KC07WeakEncryption(), s) == [
        "kdc.conf/realms/KERBO.LAB/supported_enctypes",
        "krb5.conf/libdefaults/allow_weak_crypto",
        "host/legacy.kerbo.lab@KERBO.LAB",
    ]


def test_tc_kc_08_25_hours_flagged_24_not():
    s = snap(config=[ConfigSetting("kdc.conf", "realms/KERBO.LAB", "max_life", "25h 0m 0s"),
                     ConfigSetting("krb5.conf", "libdefaults", "ticket_lifetime", "24h")])
    assert ids(KC08TicketLifetime(), s) == ["kdc.conf/realms/KERBO.LAB/max_life"]


def test_tc_kc_09_8_days_flagged_7_not():
    s = snap(config=[ConfigSetting("kdc.conf", "realms/KERBO.LAB", "max_renewable_life", "8d 0h 0m 0s"),
                     ConfigSetting("krb5.conf", "libdefaults", "renew_lifetime", "7d")])
    assert ids(KC09RenewableLifetime(), s) == ["kdc.conf/realms/KERBO.LAB/max_renewable_life"]


def test_tc_rsk_01_kc06_kc08_kc09_scores():
    got = {r: (lambda f: (f.score, f.severity))(score_finding(Finding(r, "x", "y", 1, 1), CONFIG)) for r in ("KC-06", "KC-08", "KC-09")}
    assert got == {"KC-06": (68.0, "High"), "KC-08": (42.0, "Medium"), "KC-09": (40.0, "Medium")}


def test_tc_kc_07_deprecated_label_on_rc4_key_flagged():
    """Ubuntu 26.04's getprinc shows RC4 keys as 'DEPRECATED:arcfour-hmac'."""
    s = snap([Principal("host/legacy.kerbo.lab@KERBO.LAB", "service", key_enctypes=("DEPRECATED:arcfour-hmac",)),
              Principal("alice@KERBO.LAB", "user", key_enctypes=("aes256-cts-hmac-sha1-96",))])
    findings = list(KC07WeakEncryption().evaluate(s, CONFIG))
    assert [(f.object_id, f.observed) for f in findings] == [("host/legacy.kerbo.lab@KERBO.LAB", "arcfour-hmac")]
