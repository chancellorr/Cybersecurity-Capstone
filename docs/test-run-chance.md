# S2-01 Test Run Evidence — Chance Edwards

**Date:** November 2, 2026
**Environment:** Windows 11, Python 3.14.3
**Branch:** `s2-01-test-run-chance`

## Automated Tests

Command:

```powershell
python -m pytest
```

Result: **14 tests passed.**

## CLI Verification

Command:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m kerbo_s.cli audit --snapshot tests/fixtures/sample_snapshot.json
```

Result: The CLI completed successfully and produced a JSON finding for KC-01.

## Desktop UI Verification

Command:

```powershell
python -m kerbo_s.ui.main_window
```

Result: The Kerbo-S desktop application opened successfully. The sample snapshot loaded, and the findings table displayed a KC-01 Medium-severity finding with a score of 38.5.

## Notes

The repository uses a `src` layout without a Python packaging manifest, so `PYTHONPATH` was set to the repository's `src` directory for the CLI and desktop UI verification.