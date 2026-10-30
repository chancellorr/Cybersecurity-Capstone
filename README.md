# Cybersecurity Capstone
2026 Cybersecurity Capstone

Authors: Chance Edwards, David Pantoja, Jesscia Yescas, Ben Grider

## About

Kerbo-S is an AI-assisted Kerberos security auditor for an MIT Kerberos lab. A deterministic rule engine (KC-01 to KC-11) decides what a finding is and how risky it is. An AI service only explains findings and suggests fixes; it never decides or scores anything. Kerbo-S is read-only and never changes the Kerberos environment.

## Status

| Area | Status |
|---|---|
| MIT Kerberos lab VM | Running |
| Project documents (requirements, design, change, test plan) | Drafted, in docs/ |
| Walking skeleton (snapshot, rule KC-01, scoring, window) | Included |
| Rules KC-02 to KC-11, collectors, database, AI, reports | Sprint 2 |

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest                                                    # run the tests
python -m kerbo_s.cli audit --snapshot tests/fixtures/sample_snapshot.json
PYTHONPATH=src python -m kerbo_s.ui.main_window           # the window (needs a desktop)
```

## Layout

| Folder | Contents |
|---|---|
| src/kerbo_s | Application code: models, rules, scoring, snapshot import, engine, CLI, UI |
| config | Rule thresholds, risk baselines, app settings |
| tests | pytest tests and fixtures |
| docs | Project documents |

## How we work

1. Create a branch for each Trello card: `git checkout -b s2-08-rules-kc01-04`.
2. Commit small changes with clear messages.
3. Open a pull request on GitHub and ask a teammate to review it.
4. Merge only when the tests pass, then move the Trello card to Done.

Never commit API keys, real Kerberos keys, or real lab snapshots. Use the `OPENAI_API_KEY` environment variable.

## Team slices

| Slice | Focus |
|---|---|
| A | Lab and collectors |
| B | Audit engine and scoring |
| C | GUI and storage |
| D | AI and reports |
