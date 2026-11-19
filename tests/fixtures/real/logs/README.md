# logs-v1 fixture (Sprint 3, S3-01)

Captured from the lab KDC (kdc.kerbo.lab, realm KERBO.LAB) on 2026-11-19 with
`tools/capture_fixtures.sh logs`. Ground truth is in `expected_findings.yaml`,
written at 16:06:15 UTC, before anything was planted. The Proxmox
snapshot `before-s3-logs` was taken before planting.

## What was planted, in order (UTC, 2026-11-19)

| Time | Scenario | What was done |
|---|---|---|
| 16:08:44–16:40:16 | TV-08 dave | 10 wrong passwords, 1 every 3.5 minutes (at most 5 in any 15-minute window) |
| 16:50:01 | TV-08 bob | 10 wrong passwords in a row |
| 16:50:01 | TV-08 carol | 9 wrong passwords in a row |
| 16:53:38–16:53:39 | TV-11 | Created burstuser and calmuser (-randkey), then 120 keytab logins for burstuser and 50 for calmuser. Keytabs deleted right after |
| 16:55:21–16:56:26 | TV-05 | alice logged in, requested a ticket for HTTP/web.kerbo.lab, then ran kdestroy. ldap/dir.kerbo.lab was never requested |
| About 16:57 | TV-09 (ACL) | Added `frank@KERBO.LAB *` to kadm5.acl and restarted krb5-admin-server |
| About 17:01 | Capture | Ran the capture script (last 30 days of the journal, plus kadm5.acl) |

## Notes for reviewers

- Wrong passwords were piped with `echo` instead of typed. The KDC logs the same lines, and no password text appears in the log.
- Each kinit writes 2 AS_REQ lines: NEEDED_PREAUTH, then PREAUTH_FAILED (wrong password) or ISSUE (success). The counts above are attempts. For example, calmuser has 50 ISSUE lines and 100 AS_REQ lines in total.
- alice has 2 wrong-password attempts (typos) right before her login. That's below the KC-10 threshold and isn't a planted scenario.
- burstuser and calmuser have RC4 (arcfour-hmac) keys and no password policy, because the realm still allows RC4 from the Sprint 2 planted setup. Rules other than KC-11 may flag them.
- The log covers 30 days, so it also includes Sprint 2 activity from Nov 5–7.
- On 2026-11-14 at 06:56 the KDC restarted (likely automatic updates) with no "Started" line until the 2026-11-17 reboot.
- TV-05 has no entry in expected_findings.yaml. Chance builds it from an aged copy of this capture.
