"""Base class for audit rules. Rules are pure: Snapshot and Config in, Findings out."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from kerbo_s.config import Config
from kerbo_s.models import Finding, Snapshot


class Rule(ABC):
    id: str = ""

    @abstractmethod
    def evaluate(self, snapshot: Snapshot, config: Config) -> Iterable[Finding]:
        """Yield one Finding per violating object. Must be deterministic."""
