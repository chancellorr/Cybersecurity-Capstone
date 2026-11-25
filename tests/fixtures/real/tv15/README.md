# tv15-v1 fixture (Sprint 3, S3-10)

Captured from the lab KDC (kdc.kerbo.lab, realm KERBO.LAB) on 2026-11-25 with
`tools/capture_fixtures.sh tv15`. Ground truth is in `expected_findings.yaml`,
committed at 19:15:12 UTC, before planting.

## What was planted, in order (UTC, 2026-11-25)

| Time | What was done |
|---|---|
| 19:15:12 | Committed expected_findings.yaml |
| 19:15:59 | Created svc/backup.kerbo.lab with `addprinc -randkey -e rc4-hmac:normal` (RC4 key only, no policy) |
| About 19:16 | Added `svc/backup.kerbo.lab@KERBO.LAB *` to kadm5.acl and restarted krb5-admin-server |
| About 19:16 | Ran the capture script |

## Notes for reviewers

- TV-15 is 1 service principal with 3 problems: an RC4-only key (KC-07), an admin ACL entry not in the lab's justification list (KC-06), and an old password (KC-02). The password is new, so KC-02 only fires after Chance ages collected_at by +181 days.
- A first attempt was planted at 19:09:28, before the manifest was saved. It was deleted (principal and ACL line) and planted again after the manifest commit. No audit ran on the first attempt.
- svc/backup has no password policy, so KC-03 may also flag it. That's not part of TV-15.
- The realm still has the Sprint 2 planted scenarios and the Sprint 3 logs scenarios (for example eve/admin, host/legacy, frank, burstuser, and calmuser), so this capture has more findings than TV-15. The manifest only covers TV-15.
- After aging +181 days, every principal whose password changed in November will be older than 180 days, so KC-02 may flag most principals in the aged copy, not just svc/backup.
