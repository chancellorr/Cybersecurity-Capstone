"""Shared helper for KC-08 and KC-09: compare configured lifetimes to a limit."""
from __future__ import annotations

from kerbo_s.models import Finding
from kerbo_s.parsers.kerberos_conf import duration_seconds


def lifetime_findings(rule_id, snapshot, keys, limit_seconds, limit_label):
    for s in sorted(snapshot.config, key=lambda s: s.object_id):
        if s.key not in keys:
            continue
        seconds = duration_seconds(s.value)
        if seconds is not None and seconds > limit_seconds:
            yield Finding(rule_id, "config", s.object_id, observed=s.value.strip(), threshold=limit_label)
