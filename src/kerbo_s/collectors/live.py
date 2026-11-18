"""Live collector (FR-COL-01 to FR-COL-07, FR-COL-09, S3-04): read-only capture on the KDC.

Runs on the KDC itself (Design v2.1 Section 4) and writes a snapshot folder in the S3-05 format:
the raw files, commands.log, then hashes.json last. It uses the Python standard library only,
because the KDC has no internet access to install packages.

Run as root, from a copy of src/ on the KDC:
    sudo PYTHONPATH=~/kerbo-s/src python3 -m kerbo_s.collectors.live --out ~/snapshots/clean

Read-only by construction (NFR-SEC-01, TC-COL-06): every command goes through run_allowed,
which accepts only the list/get queries below and the journal read, with shell=False, a
timeout and an output cap. A command that is not on the list raises NotAllowed before it runs.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kerbo_s.snapshot.hashing import restrict_file, restrict_folder, write_hashes

TIMEOUT_SECONDS = 30
OUTPUT_CAP_BYTES = 50 * 1024 * 1024
INCLUDE_DEPTH = 3

NAME = re.compile(r"^[A-Za-z0-9._/@-]+$")       # principal or policy names from listprincs / getpols
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KADMIN = "kadmin.local"
JOURNAL = ["journalctl", "-u", "krb5-kdc", "--no-pager", "-o", "short-iso", "--since"]

# Files read (never written). The file log is optional: the lab KDC logs to the journal.
CONFIG_FILES = {
    "/etc/krb5.conf": "krb5.conf",
    "/etc/krb5kdc/kdc.conf": "kdc.conf",
    "/etc/krb5kdc/kadm5.acl": "kadm5.acl",
}
OPTIONAL_FILES = {
    "/var/log/krb5kdc.log": "krb5kdc-file.log",
}
_INCLUDE = re.compile(r"^\s*(include|includedir)\s+(\S+)\s*$")
_INCLUDEDIR_NAME = re.compile(r"^([A-Za-z0-9_-]+|.+\.conf)$")  # MIT profile rule for includedir files


class NotAllowed(Exception):
    """A command that is not on the allow-list (TC-COL-06)."""


class CollectionError(Exception):
    """The KDC cannot be reached at all, so there is nothing to collect (TC-UI-04)."""


def is_allowed(argv) -> bool:
    """True only for the exact read-only command shapes Kerbo-S needs."""
    argv = list(argv)
    if len(argv) == 3 and argv[0] == KADMIN and argv[1] == "-q":
        parts = argv[2].split(" ")
        if parts in (["listprincs"], ["getpols"]):
            return True
        return len(parts) == 2 and parts[0] in ("getprinc", "getpol") and bool(NAME.match(parts[1]))
    return len(argv) == len(JOURNAL) + 1 and argv[:-1] == JOURNAL and bool(DATE.match(argv[-1]))


class Collector:
    def __init__(self, out_folder, runner=subprocess.run, now=None, config_files=None,
                 optional_files=None, since_days=30):
        self.out = Path(out_folder)
        self.runner = runner
        self.now = now or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        self.config_files = CONFIG_FILES if config_files is None else config_files
        self.optional_files = OPTIONAL_FILES if optional_files is None else optional_files
        self.since = (self.now - timedelta(days=since_days)).strftime("%Y-%m-%d")
        self.errors = []      # (source, message), as in Snapshot.errors
        self.files = 0

    # Commands -----------------------------------------------------------------------------
    def run_allowed(self, argv) -> str:
        """Run one allow-listed command and return its output. Logged in commands.log."""
        argv = list(argv)
        if not is_allowed(argv):
            raise NotAllowed(f"Command not on the allow-list: {argv!r}")
        started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            result = self.runner(argv, capture_output=True, timeout=TIMEOUT_SECONDS, shell=False)
        except subprocess.TimeoutExpired:
            self._log(started, "timeout", argv)
            raise
        output = result.stdout or b""
        if len(output) > OUTPUT_CAP_BYTES:
            output = output[:OUTPUT_CAP_BYTES]
            self.errors.append((" ".join(argv), f"output cut at {OUTPUT_CAP_BYTES} bytes"))
        self._log(started, f"exit={result.returncode}", argv)
        if result.returncode != 0:
            message = (result.stderr or b"").decode("utf-8", "replace").strip() or "no error text"
            raise subprocess.CalledProcessError(result.returncode, argv, output, message)
        return output.decode("utf-8", "replace")

    def _log(self, when, status, argv) -> None:
        with open(self.out / "commands.log", "a", encoding="utf-8") as handle:
            handle.write(f"{when} {status} {' '.join(argv)}\n")

    def _kadmin(self, query: str) -> str:
        text = self.run_allowed([KADMIN, "-q", query])
        return "".join(line for line in text.splitlines(keepends=True)
                       if not line.startswith("Authenticating as principal"))

    # Output files -------------------------------------------------------------------------
    def _write(self, name: str, text: str) -> None:
        path = self.out / name
        path.write_text(text, encoding="utf-8")
        restrict_file(path)
        self.files += 1

    def _copy(self, source: Path, name: str) -> bool:
        try:
            target = self.out / name
            if not target.parent.exists():
                target.parent.mkdir(parents=True)
                restrict_folder(target.parent)
            shutil.copyfile(source, target)
            restrict_file(target)
            self._log(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "read", [str(source)])
            self.files += 1
            return True
        except OSError as exc:
            self.errors.append((name, f"cannot read {source}: {exc.strerror or exc}"))
            return False

    # Collection ---------------------------------------------------------------------------
    def collect(self) -> list:
        """Write the snapshot folder and return the collection errors. Raises CollectionError
        if kadmin.local cannot run at all."""
        if self.out.exists() and any(self.out.iterdir()):
            raise CollectionError(f"Output folder is not empty: {self.out}")
        self.out.mkdir(parents=True, exist_ok=True)
        restrict_folder(self.out)
        self._write("collected_at.txt", self.now.strftime("%Y-%m-%dT%H:%M:%S") + "\n")

        try:
            principals = self._kadmin("listprincs")
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise CollectionError(f"Cannot reach the KDC: kadmin.local listprincs failed ({_why(exc)})") from None
        self._write("listprincs.txt", principals)
        self._each("getprinc", "getprinc_{}.txt", principals)

        policies = self._step("getpols.txt", lambda: self._kadmin("getpols"))
        if policies is not None:
            self._write("getpols.txt", policies)
            self._each("getpol", "getpol_{}.txt", policies)

        log = self._step("krb5kdc.log", lambda: self.run_allowed(JOURNAL + [self.since]))
        if log is not None:
            self._write("krb5kdc.log", log)

        for source, name in self.config_files.items():
            if self._copy(Path(source), name) and name in ("krb5.conf", "kdc.conf"):
                self._follow_includes(Path(source), depth=1, seen={Path(source)})
        for source, name in self.optional_files.items():
            if Path(source).is_file():
                self._copy(Path(source), name)

        if self.errors:
            self._write("collection_errors.txt", "".join(f"{s}: {m}\n" for s, m in self.errors))
        write_hashes(self.out)
        _give_to_sudo_user(self.out)
        return self.errors

    def _step(self, source, action):
        try:
            return action()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            self.errors.append((source, _why(exc)))
            return None

    def _each(self, query, pattern, listing) -> None:
        for name in listing.splitlines():
            name = name.strip()
            if not name:
                continue
            filename = pattern.format(name.replace("/", "_"))
            if not NAME.match(name):
                self.errors.append((filename, f"name not collected (unexpected characters): {name!r}"))
                continue
            text = self._step(filename, lambda: self._kadmin(f"{query} {name}"))
            if text is not None:
                self._write(filename, text)

    def _follow_includes(self, path: Path, depth: int, seen: set) -> None:
        """Copy files named by include / includedir lines into included/ so they are hashed (depth 3)."""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            match = _INCLUDE.match(line)
            if not match:
                continue
            kind, target = match.group(1), Path(match.group(2))
            if depth > INCLUDE_DEPTH:
                self.errors.append((str(path), f"{kind} {target}: deeper than {INCLUDE_DEPTH} levels, not followed"))
                continue
            if kind == "include":
                targets = [target]
            else:
                try:
                    targets = sorted(p for p in target.iterdir() if p.is_file() and _INCLUDEDIR_NAME.match(p.name))
                except OSError as exc:
                    self.errors.append((str(target), f"includedir cannot be read: {exc.strerror or exc}"))
                    continue
            for item in targets:
                if item in seen:
                    self.errors.append((str(item), "include loop, not followed again"))
                    continue
                seen.add(item)
                if self._copy(item, included_name(item)):
                    self._follow_includes(item, depth + 1, seen)


def included_name(path) -> str:
    """Where an included file is stored in the snapshot: /etc/krb5.conf.d/crypto.conf ->
    included/etc_krb5.conf.d_crypto.conf. Chance's include reader (S3-12) should read this naming."""
    text = str(path).replace("\\", "/").replace(":", "").strip("/")  # Windows paths too, for the tests
    return "included/" + text.replace("/", "_")


def _why(exc) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        return f"exit {exc.returncode}: {exc.stderr}"
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timed out after {TIMEOUT_SECONDS} s"
    if isinstance(exc, FileNotFoundError):
        return f"{exc.filename or 'program'} not found"
    return str(exc)


def _give_to_sudo_user(folder: Path) -> None:
    """Run with sudo, the files belong to root; give them to the user who ran sudo so scp works."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.name != "posix" or os.geteuid() != 0 or not uid or not gid:
        return
    for path in [folder, *folder.rglob("*")]:
        os.chown(path, int(uid), int(gid))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kerbo-s-collect", description="Read-only Kerberos capture on the KDC")
    parser.add_argument("--out", required=True, help="new, empty folder for the snapshot")
    parser.add_argument("--since-days", type=int, default=30, help="days of KDC log to read (default 30)")
    args = parser.parse_args(argv)
    collector = Collector(args.out, since_days=args.since_days)
    try:
        errors = collector.collect()
    except CollectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Saved {collector.files} files to {args.out}")
    for source, message in errors:
        print(f"  warning: {source}: {message}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
