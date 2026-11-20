from datetime import datetime, timezone

from kerbo_s.models import Finding


from .prompt import PROMPT_VERSION, build_prompt
from .provider import Provider
from .sanitize import to_payload


def analyze_audit(conn, audit_id, findings, provider: Provider, settings):
    """Generate and store one advisory response per saved finding."""
    tokens: dict[str, str] = {}
    outputs = []

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
        response = provider.complete(prompt)
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        outputs.append(
            (
                audit_id,
                row["id"],
                settings["provider"],
                settings["model"],
                PROMPT_VERSION,
                created_at,
                response,
            )
        )
    with conn:
        conn.executemany(
            """
            INSERT INTO ai_outputs (
                audit_id, finding_id, kind, provider, model,
                prompt_version, created_at, status, output_json
            )
            VALUES (?, ?, 'finding', ?, ?, ?, ?, 'ok', ?)
            """,
            outputs,
        )
