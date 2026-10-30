"""Loads and validates rule thresholds and risk-factor baselines (FR-AUD-03, FR-RSK-03)."""
from __future__ import annotations

import yaml

FACTOR_NAMES = ("impact", "exploitability", "exposure", "compliance")


class Config:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        cls._validate(data)
        return cls(data)

    @staticmethod
    def _validate(data: dict) -> None:
        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError("config must contain a 'rules' section")
        for rule_id, entry in data["rules"].items():
            factors = entry.get("factors", {})
            for name in FACTOR_NAMES:
                value = factors.get(name)
                if not isinstance(value, (int, float)) or not 0 <= value <= 100:
                    raise ValueError(f"{rule_id}: factor '{name}' must be a number from 0 to 100")

    def threshold(self, rule_id: str, key: str):
        return self.data["rules"][rule_id]["thresholds"][key]

    def factors(self, rule_id: str) -> dict:
        return self.data["rules"][rule_id]["factors"]
