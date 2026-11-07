"""KC-07: Weak encryption (RC4, DES, 3DES) configured, allowed, or held by a principal."""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule

ENCTYPE_KEYS = ("supported_enctypes", "permitted_enctypes", "default_tkt_enctypes", "default_tgs_enctypes")
WEAK_PREFIXES = ("rc4", "arcfour", "des")   # des also covers des3-*; aes types never start with "des"


def weak_types(value: str):
    """Weak enctype names in a setting or key list.

    Each token can carry a label on either side of a colon: a salt after it in kdc.conf
    ("rc4-hmac:normal"), or a status before it in getprinc output on newer MIT releases
    ("DEPRECATED:arcfour-hmac"). Every part is checked, so both forms are caught.
    """
    names = [part.lower() for token in value.replace(",", " ").split() for part in token.split(":")]
    return sorted({n for n in names if n.startswith(WEAK_PREFIXES)})


class KC07WeakEncryption(Rule):
    id = "KC-07"

    def evaluate(self, snapshot, config):
        for s in sorted(snapshot.config, key=lambda s: s.object_id):
            if s.key in ENCTYPE_KEYS and (weak := weak_types(s.value)):
                yield Finding(self.id, "config", s.object_id, observed=" ".join(weak), threshold="no RC4, DES or 3DES")
            elif s.key == "allow_weak_crypto" and s.value.strip().lower() in ("true", "yes", "1"):
                yield Finding(self.id, "config", s.object_id, observed=s.value.strip(), threshold="false")
        for p in sorted(snapshot.principals, key=lambda p: p.name):
            if weak := weak_types(" ".join(p.key_enctypes)):
                yield Finding(self.id, "principal", p.name, observed=" ".join(weak), threshold="no RC4, DES or 3DES keys")
