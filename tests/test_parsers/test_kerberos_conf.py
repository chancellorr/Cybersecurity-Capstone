from kerbo_s.parsers.kerberos_conf import duration_seconds, parse_profile

KDC_CONF = """[kdcdefaults]
    kdc_ports = 750,88

[realms]
    KERBO.LAB = {
        database_name = /var/lib/krb5kdc/principal
        max_life = 25h 0m 0s
        max_renewable_life = 8d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal rc4-hmac:normal
    }
"""

KRB5_CONF = """[libdefaults]
\tdefault_realm = KERBO.LAB
\tallow_weak_crypto = true
\tticket_lifetime = 24h
# a comment
[realms]
\tKERBO.LAB = {
\t\tkdc = kdc.kerbo.lab
\t}
"""


def settings(text, label):
    found, errors = parse_profile(text, label)
    assert errors == []
    return {s.object_id: s.value for s in found}


def test_tc_col_03_kdc_conf_realm_settings():
    s = settings(KDC_CONF, "kdc.conf")
    assert s["kdc.conf/realms/KERBO.LAB/max_life"] == "25h 0m 0s"
    assert s["kdc.conf/realms/KERBO.LAB/supported_enctypes"].endswith("rc4-hmac:normal")
    assert s["kdc.conf/kdcdefaults/kdc_ports"] == "750,88"


def test_tc_col_03_krb5_conf_libdefaults_and_tabs():
    s = settings(KRB5_CONF, "krb5.conf")
    assert s["krb5.conf/libdefaults/allow_weak_crypto"] == "true"
    assert s["krb5.conf/realms/KERBO.LAB/kdc"] == "kdc.kerbo.lab"


def test_tc_col_03_bad_line_is_an_error_not_a_crash():
    found, errors = parse_profile("[libdefaults]\n  this is not a setting\n  ok = 1\n", "krb5.conf")
    assert [s.key for s in found] == ["ok"] and len(errors) == 1


def test_tc_col_03_durations():
    assert duration_seconds("25h 0m 0s") == 90000
    assert duration_seconds("8d 0h 0m 0s") == 8 * 86400
    assert duration_seconds("7d") == 7 * 86400
    assert duration_seconds("24h") == 86400
    assert duration_seconds("10:00:00") == 36000
    assert duration_seconds("36000") == 36000
    assert duration_seconds("forever") is None
