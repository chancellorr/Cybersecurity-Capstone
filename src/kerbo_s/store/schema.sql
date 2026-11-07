-- Kerbo-S SQLite schema (Design Document, Section 6.2). Sprint 2 tables only;
-- ai_outputs and reports come with the AI and report work in Sprint 3.
-- Findings are immutable (FR-DB-02, threat TM-05): the two triggers at the end
-- reject any UPDATE or DELETE on them. Review notes live in their own table.

CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    config_hash TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    source TEXT NOT NULL,
    command_or_path TEXT NOT NULL,
    collected_at TEXT,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    stored_path TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    rule_id TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    observed TEXT,
    threshold TEXT,
    impact REAL, exploitability REAL, exposure REAL, compliance REAL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    artifact_id INTEGER REFERENCES artifacts(id)
);

CREATE TABLE IF NOT EXISTS reviews (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id),
    status TEXT NOT NULL DEFAULT 'open',
    note TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS collection_errors (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS findings_no_update
BEFORE UPDATE ON findings
BEGIN SELECT RAISE(ABORT, 'findings are immutable'); END;

CREATE TRIGGER IF NOT EXISTS findings_no_delete
BEFORE DELETE ON findings
BEGIN SELECT RAISE(ABORT, 'findings are immutable'); END;
