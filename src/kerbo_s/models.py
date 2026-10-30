"""Typed hand-offs between pipeline stages (Design Document, Sections 6.1 and 7)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(frozen=True)
class Principal:
    name: str
    kind: str  # "user", "service", "admin" or "internal"
    last_password_change: Optional[datetime] = None
    last_successful_auth: Optional[datetime] = None
    policy: Optional[str] = None
    key_enctypes: tuple = ()

    def password_age_days(self, now: datetime) -> Optional[int]:
        """Age is measured against the snapshot time, never the current clock."""
        if self.last_password_change is None:
            return None
        return (now - self.last_password_change).days


@dataclass
class Snapshot:
    collected_at: datetime
    principals: list = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    object_type: str
    object_id: str
    observed: Any
    threshold: Any
    score: float = 0.0
    severity: str = ""
    factors: dict = field(default_factory=dict)
