# Test runs

| Date | Who | Command | Result |
|---|---|---|---|
| 2026-10-30 | Jessica Yescas | python -m pytest | 14 passed in 0.73s |
| 2026-10-30 | Jessica Yescas | python -m kerbo_s.cli audit --snapshot tests/fixtures/sample_snapshot.json | 1 finding: KC-01, alice@LAB.LOCAL, Medium, 38.5 |
| 2026-10-30 | Jessica Yescas | python -m kerbo_s.ui.main_window | Window opens; Run Audit shows 1 finding (Medium, 38.5, KC-01, observed 150, threshold 90) |