"""Parser for MIT Kerberos profile files: krb5.conf and kdc.conf (FR-COL-03)."""
from __future__ import annotations

import re

from kerbo_s.models import ConfigSetting

_SECTION = re.compile(r"^\[(?P<name>[^\]]+)\]$")
_OPEN = re.compile(r"^(?P<name>[^=\s]+)\s*=\s*\{$")
_PAIR = re.compile(r"^(?P<key>[^=\s]+)\s*=\s*(?P<value>.*)$")
_DIRECTIVE = re.compile(r"^(include|includedir|module)\s+\S")  # MIT profile directives; the files they name are not read


def parse_profile(text: str, file_label: str):
    """Return (settings, errors). Sections nest as 'realms/KERBO.LAB'."""
    settings, errors = [], []
    path = []          # ['realms', 'KERBO.LAB']
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or _DIRECTIVE.match(line):
            continue
        if m := _SECTION.match(line):
            path = [m.group("name").strip()]
        elif m := _OPEN.match(line):
            path.append(m.group("name"))
        elif line == "}":
            if len(path) > 1:
                path.pop()
            else:
                errors.append((file_label, f"line {number}: unexpected }}"))
        elif m := _PAIR.match(line):
            if not path:
                errors.append((file_label, f"line {number}: setting outside a section"))
                continue
            settings.append(ConfigSetting(file_label, "/".join(path), m.group("key"), m.group("value").strip()))
        else:
            errors.append((file_label, f"line {number}: cannot parse {line!r}"))
    return settings, errors


_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def duration_seconds(value: str):
    """MIT durations: '36000', '10:00:00', '25h 0m 0s', '8d 0h 0m 0s', '7d', '1d10h'. None if unreadable."""
    text = value.strip().lower()
    if text.isdigit():
        return int(text)
    if re.fullmatch(r"\d+:\d{2}(:\d{2})?", text):
        parts = [int(p) for p in text.split(":")] + [0]
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    pieces = re.findall(r"(\d+)\s*([dhms])", text)
    if pieces and re.fullmatch(r"(\s*\d+\s*[dhms])+\s*", text):
        return sum(int(n) * _UNITS[u] for n, u in pieces)
    return None
