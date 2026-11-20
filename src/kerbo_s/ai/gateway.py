from datetime import datetime, timezone

from kerbo_s.models import Finding

import json


from .prompt import PROMPT_VERSION, build_prompt
from .provider import Provider, ProviderUnavailable
from .sanitize import to_payload

def _valid_advisory(response: str) -> bool:
    try:
        data = json.loads(response)
    except json.JSONDecodeError:
        return False

    return (
        isinstance(data, dict)
        and set(data) == {"explanation", "risk_context", "remediation"}
        and isinstance(data["explanation"], str)
        and isinstance(data["risk_context"], str)
        and isinstance(data["remediation"], list)
        and all(isinstance(step, str) for step in data["remediation"])
    )

def analyze_audit(conn, audit_id, findings, provider: Provider, settings):
    """Generate and store one advisory response per saved finding."""
    tokens: dict[str, str] = {}
    outputs = []
    message = None

    for row in findings:
        finding = Finding(
            rule_id=row["rule_id"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            observed=row["observed"],
            threshold=row["threshold"],
            severity=row["severity"],
            score=row["score"],
        )
        prompt = build_prompt(to_payload(finding, tokens))
        status = "unavailable"
        output_json = None

        try:
            for _ in range(2):
                response = provider.complete(prompt)
                if _valid_advisory(response):
                    status = "ok"
                    output_json = response
                    break
        except ProviderUnavailable as exc:
            message = f"AI analysis unavailable: {exc}"
            break

        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        outputs.append(
            (
                audit_id,
                row["id"],
                settings["provider"],
                settings["model"],
                PROMPT_VERSION,
                created_at,
                status,
                output_json
            )
        )
    with conn:
        conn.executemany(
            """
            INSERT INTO ai_outputs (
                audit_id, finding_id, kind, provider, model,
                prompt_version, created_at, status, output_json
            )
            VALUES (?, ?, 'finding', ?, ?, ?, ?, ?, ?)
            """,
            outputs,
        )
    return message
