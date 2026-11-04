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


@dataclass(frozen=True)
class Policy:
    name: str
    min_length: Optional[int] = None
    max_life_days: Optional[int] = None
    min_life_days: Optional[int] = None
    history: Optional[int] = None
    max_failures: Optional[int] = None


@dataclass(frozen=True)
class ConfigSetting:
    file: str
    section: str
    key: str
    value: str

    @property
    def object_id(self) -> str:
        return f"{self.file}/{self.section}/{self.key}"


@dataclass
class Snapshot:
    collected_at: datetime
    principals: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    config: list = field(default_factory=list)
    errors: list = field(default_factory=list)


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
