"""Snapshot import (FR-COL-08). Hash verification (FR-COL-09) is added in Sprint 3."""
from __future__ import annotations

import json
from datetime import datetime

from kerbo_s.models import Principal, Snapshot

REQUIRED = ("collected_at",)


class SnapshotError(Exception):
    """The snapshot file is missing, not JSON, or missing required fields (FR-COL-07, TC-UI-06)."""


def _parse_time(value):
    return datetime.fromisoformat(value) if value else None


def load_snapshot(path: str) -> Snapshot:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        raise SnapshotError(f"Snapshot file not found: {path}") from None
    except IsADirectoryError:
        raise SnapshotError(f"Snapshot path is a folder, not a file: {path}") from None
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"Snapshot is not valid JSON ({path}, line {exc.lineno})") from None
    if not isinstance(raw, dict):
        raise SnapshotError(f"Snapshot must be a JSON object: {path}")
    missing = [key for key in REQUIRED if key not in raw]
    if missing:
        raise SnapshotError(f"Snapshot is missing required fields: {', '.join(missing)}")
    try:
        collected_at = datetime.fromisoformat(raw["collected_at"])
    except (TypeError, ValueError):
        raise SnapshotError(f"Snapshot collected_at is not a valid date: {raw['collected_at']!r}") from None

    principals = []
    for number, item in enumerate(raw.get("principals", []), start=1):
        try:
            principals.append(Principal(
                name=item["name"],
                kind=item["kind"],
                last_password_change=_parse_time(item.get("last_password_change")),
                last_successful_auth=_parse_time(item.get("last_successful_auth")),
                policy=item.get("policy"),
                key_enctypes=tuple(item.get("key_enctypes", [])),
            ))
        except KeyError as exc:
            raise SnapshotError(f"Principal entry {number} is missing the field {exc.args[0]!r}") from None
        except (TypeError, ValueError) as exc:
            raise SnapshotError(f"Principal entry {number} has an invalid value: {exc}") from None
    return Snapshot(collected_at=collected_at, principals=principals)
