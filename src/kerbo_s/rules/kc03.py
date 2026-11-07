"""KC-03: Weak password policy (default: minimum length under 12), or a principal with no policy.

MIT's built-in principals (kind "internal": K/M, krbtgt/*, kadmin/*, kiprop/*) are created
without a policy by Kerberos itself, so they are skipped; otherwise a clean realm could never
produce zero findings (TC-KC-12).
"""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule

CHECKED_KINDS = ("user", "service", "admin")


class KC03WeakPasswordPolicy(Rule):
    id = "KC-03"

    def evaluate(self, snapshot, config):
        limit = config.threshold(self.id, "min_length")
        for policy in sorted(snapshot.policies, key=lambda p: p.name):
            if policy.min_length is not None and policy.min_length < limit:
                yield Finding(self.id, "policy", policy.name, observed=policy.min_length, threshold=limit)
        for principal in sorted(snapshot.principals, key=lambda p: p.name):
            if principal.kind in CHECKED_KINDS and not principal.policy:
                yield Finding(self.id, "principal", principal.name, observed="no policy", threshold=limit)
