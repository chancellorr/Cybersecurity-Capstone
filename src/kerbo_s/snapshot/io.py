"""Snapshot export and import (FR-COL-08) with hash checking (FR-COL-09).

A snapshot is either a JSON file (principals only, Sprint 1 format) or a snapshot folder:
the raw files as captured, plus snapshot.json (every parsed model) and hashes.json. Importing
a folder checks the hashes first, then reads the raw files with load_fixture_dir.
"""
from __future__ import annotations

import dataclasses
import json
import shutil
from datetime import datetime
from pathlib import Path

from kerbo_s.models import Principal, Snapshot
from kerbo_s.parsers.kadmin import load_fixture_dir
from kerbo_s.snapshot.hashing import (
    HASHES_FILE, NOT_HASHED, restrict_file, restrict_folder, verify_hashes, write_hashes,
)

SNAPSHOT_JSON = "snapshot.json"
# Files in a fixture folder that describe a scenario rather than the KDC; never copied into a snapshot.
NOT_RAW = {HASHES_FILE, SNAPSHOT_JSON, "expected_findings.yaml", "README.md"}

REQUIRED = ("collected_at",)


class SnapshotError(Exception):
    """The snapshot file is missing, not JSON, or missing required fields (FR-COL-07, TC-UI-06)."""


def _parse_time(value):
    return datetime.fromisoformat(value) if value else None


def load_snapshot(path: str) -> Snapshot:
    """Load a JSON snapshot file, or import a snapshot or fixture folder (hashes checked)."""
    if Path(path).is_dir():
        return import_snapshot(path)
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
    return Snapshot(collected_at=collected_at, principals=principals, integrity=NOT_HASHED)


def _json_value(value):
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"cannot write {type(value).__name__} to snapshot.json")


def export_snapshot(snapshot: Snapshot, raw_folder, out_folder) -> Path:
    """Write a snapshot folder: copies of the raw files, snapshot.json, then hashes.json last.

    raw_folder is where the raw files were captured (a collector output or fixture folder).
    out_folder must not exist yet, or be empty. Folders are 700 and files 600 (NFR-SEC-02).
    """
    raw_folder, out_folder = Path(raw_folder), Path(out_folder)
    if not raw_folder.is_dir():
        raise SnapshotError(f"Raw folder not found: {raw_folder}")
    if out_folder.exists() and any(out_folder.iterdir()):
        raise SnapshotError(f"Snapshot folder is not empty: {out_folder}")
    out_folder.mkdir(parents=True, exist_ok=True)
    restrict_folder(out_folder)

    for source in sorted(raw_folder.rglob("*")):
        relative = source.relative_to(raw_folder)
        if not source.is_file() or source.is_symlink() or relative.as_posix() in NOT_RAW:
            continue
        target = out_folder / relative
        if not target.parent.exists():
            target.parent.mkdir(parents=True)
            restrict_folder(target.parent)
        shutil.copyfile(source, target)
        restrict_file(target)

    data = dataclasses.asdict(snapshot)
    data.pop("integrity", None)
    json_path = out_folder / SNAPSHOT_JSON
    json_path.write_text(json.dumps(data, indent=2, default=_json_value) + "\n", encoding="utf-8")
    restrict_file(json_path)

    write_hashes(out_folder)
    return out_folder


def import_snapshot(folder) -> Snapshot:
    """Check the folder's hashes, then load its raw files.

    A hash problem does not stop the import: each problem becomes an error on the snapshot and
    snapshot.integrity is "mismatch", so the audit runs but is flagged (TC-COL-09). A folder with
    no hashes.json (a Sprint 2 fixture folder) loads as "not hashed".
    """
    status, problems = verify_hashes(folder)
    try:
        snapshot = load_fixture_dir(folder)
    except (FileNotFoundError, ValueError) as exc:
        raise SnapshotError(str(exc)) from None
    snapshot.errors.extend(problems)
    snapshot.integrity = status
    return snapshot
