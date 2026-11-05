"""KC-06: Administrative principal without a documented justification."""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.rules.base import Rule


class KC06UnjustifiedAdmin(Rule):
    id = "KC-06"

    def evaluate(self, snapshot, config):
        approved = config.approved_admins()
        for principal in sorted(snapshot.principals, key=lambda p: p.name):
            if principal.kind == "admin" and principal.name not in approved:
                yield Finding(self.id, "principal", principal.name,
                              observed="admin, not in justification file", threshold="listed and justified")
