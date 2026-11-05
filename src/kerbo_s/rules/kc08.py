"""KC-08: Configured ticket lifetime longer than the limit (default 24 hours)."""
from kerbo_s.rules.base import Rule
from kerbo_s.rules.lifetimes import lifetime_findings


class KC08TicketLifetime(Rule):
    id = "KC-08"

    def evaluate(self, snapshot, config):
        hours = config.threshold(self.id, "max_hours")
        yield from lifetime_findings(self.id, snapshot, ("max_life", "ticket_lifetime"), hours * 3600, f"{hours}h")
