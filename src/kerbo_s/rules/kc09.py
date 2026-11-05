"""KC-09: Configured renewable lifetime longer than the limit (default 7 days)."""
from kerbo_s.rules.base import Rule
from kerbo_s.rules.lifetimes import lifetime_findings


class KC09RenewableLifetime(Rule):
    id = "KC-09"

    def evaluate(self, snapshot, config):
        days = config.threshold(self.id, "max_days")
        yield from lifetime_findings(self.id, snapshot, ("max_renewable_life", "renew_lifetime"), days * 86400, f"{days}d")
