# Advisory: SSRF filter bypass via untrimmed host in `busbar-unit-trust`

## Summary

`busbar-unit-trust`'s destination guard (`crates/busbar-unit-trust/src/net.rs`,
`extract_normalized_host` / `strip_whatwg_removed`) was extracted from the live
`busbar-substrate::net_guard` during the 1.6.0 plane-extraction work without carrying over the
WHATWG basic URL parser's leading/trailing trim (C0 controls and space), only its interior
tab/LF/CR deletion. A destination carrying a single trailing space
(`"https://10.99.99.99 "` — what an unquoted YAML scalar or a console copy-paste leaves behind)
parsed to a host the guard could not match against `blocked_metadata_hosts`, while the connecting
stack trims the space and dials the blocked address anyway. A leading space
(`" http://169.254.169.254/"`) hid the scheme instead, so `strip_scheme` returned `None` and the
URL passed with no host ever examined. Because the token endpoints POST the operator's
`client_id`/`client_secret` to the configured URL verbatim, this is SSRF to cloud metadata
(`169.254.169.254`) with credential exfiltration as the payload.

## Affected versions (measured)

**None released.** `busbar-unit-trust` does not exist prior to the 1.6.0 plane-extraction work:

- The crate was introduced by `657b93981` ("busbar-unit-auth, busbar-unit-trust: the 1.5.5 auth
  chain and destination verification as units"), 2026-09-04 — not an ancestor of `v1.5.5`
  (`git merge-base --is-ancestor 657b93981 v1.5.5` → no).
- `net.rs` itself was added by `0aad54bfa`, 2026-09-05 — also not an ancestor of `v1.5.5`.
- The published 1.5.5 binary (`testing/shadow-oracle/golden/1.5.5/meta.json`,
  `binary_sha256: 84bde0a0…`, tag `v1.5.5` = `a71b21e9f`) predates the crate entirely: it has no
  `crates/busbar-unit-trust` tree at all.
- The bug was created and fixed within the same unreleased line of work: the differential exists
  only between the 1.6.0 extraction (`0aad54bfa`) and its fix (`2bc50d2cb`, both 2026-09).

The vulnerable code was never in a shipped artifact.

## Fixed in

- `2bc50d2cb` — "trust unit: restore the WHATWG first step's leading/trailing trim, at parity with
  the substrate" (cherry-picked from `c004b413a`), 2026-09-07.
- Present on `origin/integration/oracle-phase0` and its `keep-*` descendants. Not applicable to any
  released line (see above) and not present on `origin/dev`, `origin/qa`, or `origin/main`, none of
  which carry `busbar-unit-trust` at all yet.

## Severity (per SECURITY.md's scale)

Would be **Critical** (SSRF to cloud metadata + credential exfiltration, matching the "SSRF via a
config-controlled upstream" and "Credential leakage" scope items in SECURITY.md) had it ever
reached an operator. As measured, it did not.

## Exposure statement

The vulnerable code was introduced and fixed entirely within unreleased 1.6.0 development; it was
never on a path reachable by any tagged release, including `v1.5.5`, the current published
version. **No advisory is owed to operators and no CVE is warranted** — this is pre-release
hardening, not a regression in shipped software. Recorded here so the disclosure question is
answered rather than left to be inferred from an empty commit body.

## Backport

None owed. No released line ever carried the defect.

## Credit

Internal audit.
