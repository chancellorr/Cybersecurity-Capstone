from unicodedata import category

from kerbo_s.models import Finding


def _strip_controls(text: str) -> str:
    return "".join(char for char in text if category(char) not in {"Cc", "Cf"})


def _clean_value(value: object, object_id: str, token: str) -> str:
    text = _strip_controls(str(value))
    clean_id = _strip_controls(object_id)
    if clean_id:
        text = text.replace(clean_id, token)
    return text[:200]


def to_payload(finding: Finding, tokens: dict[str, str]) -> dict[str, object]:
    """Build an allow-listed payload and keep the token map local to the audit."""
    prefix = f"{finding.object_type}-"
    token = next(
        (
            key
            for key, name in tokens.items()
            if key.startswith(prefix) and name == finding.object_id
        ),
        None,
    )
    if token is None:
        number = 1
        while f"{prefix}{number}" in tokens:
            number += 1
        token = f"{prefix}{number}"
        tokens[token] = finding.object_id

    return {
        "rule_id": finding.rule_id,
        "object_type": finding.object_type,
        "object_token": token,
        "observed": _clean_value(finding.observed, finding.object_id, token),
        "threshold": _clean_value(finding.threshold, finding.object_id, token),
        "severity": finding.severity,
        "score": finding.score,
    }
