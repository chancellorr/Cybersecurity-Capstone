"""KC-01: User password age violation (default: older than 90 days)."""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule


class KC01PasswordAge(Rule):
    id = "KC-01"

    def evaluate(self, snapshot, config):
        limit = config.threshold(self.id, "max_age_days")
        for principal in sorted(snapshot.principals, key=lambda p: p.name):
            if principal.kind != "user":
                continue
            age = principal.password_age_days(snapshot.collected_at)
            if age is not None and age > limit:
                yield Finding(self.id, "principal", principal.name, observed=age, threshold=limit)
