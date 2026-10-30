"""Snapshot import (FR-COL-08). Hash verification (FR-COL-09) is added in Sprint 2."""
from __future__ import annotations

import json
from datetime import datetime

from kerbo_s.models import Principal, Snapshot


def _parse_time(value):
    return datetime.fromisoformat(value) if value else None


def load_snapshot(path: str) -> Snapshot:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    principals = [
        Principal(
            name=item["name"],
            kind=item["kind"],
            last_password_change=_parse_time(item.get("last_password_change")),
            last_successful_auth=_parse_time(item.get("last_successful_auth")),
            policy=item.get("policy"),
            key_enctypes=tuple(item.get("key_enctypes", [])),
        )
        for item in raw.get("principals", [])
    ]
    return Snapshot(collected_at=datetime.fromisoformat(raw["collected_at"]), principals=principals)
