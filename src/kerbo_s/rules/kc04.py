"""KC-04: Inactive user principal (default: no successful authentication in more than 180 days).

A never-authenticated account is measured from its creation date. getprinc does not show a
creation date, so the last password change is used instead: an account's first password is
set when it is created.
"""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule


class KC04InactiveUser(Rule):
    id = "KC-04"

    def evaluate(self, snapshot, config):
        limit = config.threshold(self.id, "inactive_days")
        for principal in sorted(snapshot.principals, key=lambda p: p.name):
            if principal.kind != "user":
                continue
            since = principal.last_successful_auth or principal.last_password_change
            if since is None:
                continue
            days = (snapshot.collected_at - since).days
            if days > limit:
                observed = days if principal.last_successful_auth else f"{days} (never authenticated)"
                yield Finding(self.id, "principal", principal.name, observed=observed, threshold=limit)
