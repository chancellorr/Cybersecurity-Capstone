"""Hashes taken when a snapshot is written and checked when it is imported (FR-COL-09, TC-COL-09, TV-14).

A snapshot folder holds the raw files as captured, plus hashes.json with the SHA-256 of every
other file in the folder. On import every hash is checked first, so a file changed, removed
or added after capture is reported and the audit is flagged instead of trusted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

HASHES_FILE = "hashes.json"
ALGORITHM = "sha256"

VERIFIED = "verified"
MISMATCH = "mismatch"
NOT_HASHED = "not hashed"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _hashed_files(folder: Path) -> list:
    """Every regular file in the folder and its subfolders except hashes.json, as sorted relative paths."""
    files = []
    for path in folder.rglob("*"):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(folder).as_posix()
            if relative != HASHES_FILE:
                files.append(relative)
    return sorted(files)


def write_hashes(folder) -> dict:
    """Write hashes.json for every file in the folder (call it last, after all files are written)."""
    folder = Path(folder)
    hashes = {name: _sha256(folder / name) for name in _hashed_files(folder)}
    target = folder / HASHES_FILE
    target.write_text(json.dumps({"algorithm": ALGORITHM, "files": hashes}, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    restrict_file(target)
    return hashes


def verify_hashes(folder):
    """Return (status, problems).

    status is VERIFIED, MISMATCH or NOT_HASHED (the folder has no hashes.json, for example a
    Sprint 2 fixture folder). problems is a list of (source, message) pairs, one per changed,
    missing or extra file, in the same shape as Snapshot.errors.
    """
    folder = Path(folder)
    hashes_path = folder / HASHES_FILE
    if not hashes_path.is_file():
        return NOT_HASHED, []
    try:
        data = json.loads(hashes_path.read_text(encoding="utf-8"))
        expected = data["files"]
        if data.get("algorithm") != ALGORITHM or not isinstance(expected, dict):
            raise ValueError("unsupported format")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return MISMATCH, [(HASHES_FILE, f"hash list cannot be read: {exc}")]

    problems = []
    present = set(_hashed_files(folder))
    for name in sorted(expected):
        if name not in present:
            problems.append((name, "hash mismatch: file listed in hashes.json is missing"))
        elif _sha256(folder / name) != expected[name]:
            problems.append((name, "hash mismatch: file changed after capture"))
    for name in sorted(present - set(expected)):
        problems.append((name, "hash mismatch: file added after capture"))
    return (MISMATCH if problems else VERIFIED), problems


def restrict_folder(path) -> None:
    """Owner-only folder (700), NFR-SEC-02. Ignored where the OS has no Unix permissions."""
    if os.name == "posix":
        os.chmod(path, 0o700)


def restrict_file(path) -> None:
    """Owner-only file (600), NFR-SEC-02. Ignored where the OS has no Unix permissions."""
    if os.name == "posix":
        os.chmod(path, 0o600)
