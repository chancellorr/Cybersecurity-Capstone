"""KC-02: Service principal password rotation violation (default: older than 180 days)."""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule


class KC02ServicePasswordAge(Rule):
    id = "KC-02"

    def evaluate(self, snapshot, config):
        limit = config.threshold(self.id, "max_age_days")
        for principal in sorted(snapshot.principals, key=lambda p: p.name):
            if principal.kind != "service":
                continue
            age = principal.password_age_days(snapshot.collected_at)
            if age is not None and age > limit:
                yield Finding(self.id, "principal", principal.name, observed=age, threshold=limit)
