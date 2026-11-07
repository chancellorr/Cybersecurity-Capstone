# Aged fixtures (aged-v1)

Copy of planted-v1 with the dates in the six getprinc lines listed in Ben's Sprint 2 Guide, Phase 3 Part D, moved back to test KC-01, KC-02 and KC-04. All other content is real KDC output.

Ages are whole days before collected_at (2026-11-07T05:10:03 UTC), counted the way the code counts them: `(collected_at - date).days`.

| File | Line | New value | Age (days) | Expected |
|---|---|---|---|---|
| getprinc_alice@KERBO.LAB.txt | Last password change | Fri Aug 07 17:06:59 UTC 2026 | 91 | KC-01 finding (TV-01) |
| getprinc_dave@KERBO.LAB.txt | Last password change | Sun Aug 09 04:34:41 UTC 2026 | 90 | No finding, boundary |
| getprinc_HTTP_web.kerbo.lab@KERBO.LAB.txt | Last password change | Sun May 10 04:37:27 UTC 2026 | 181 | KC-02 finding (TV-02) |
| getprinc_ldap_dir.kerbo.lab@KERBO.LAB.txt | Last password change | Mon May 11 04:37:57 UTC 2026 | 180 | No finding, boundary |
| getprinc_frank@KERBO.LAB.txt | Last successful authentication | Sun May 10 04:35:14 UTC 2026 (was [never]) | 181 | KC-04 finding (TV-04) |
| getprinc_dave@KERBO.LAB.txt | Last successful authentication | Tue May 12 04:34:41 UTC 2026 (was [never]) | 179 | No finding, boundary |

alice is 92 calendar days back because her time of day (17:06:59) is later than the capture time (05:10:03), so 91 full days needs 1 extra calendar day. The [never] lines reuse the time from that principal's own Last password change line.

To see every change: `diff -r tests/fixtures/real/planted tests/fixtures/real/aged`
