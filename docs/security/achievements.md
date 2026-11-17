# Security and quality practices

A short list of the practices Busbar uses, each linked to the document that holds the evidence or
the limits. It states what is in place, not that a particular revision has passed qualification:
the [security posture](1.6.0-security-posture.md) records the baseline and the open gaps, and
[What CI checks](../ci.md) separates a job that is defined from a job that has run and passed.

| Practice | Evidence |
|---|---|
| A written threat model: trust boundaries, assets, limits and requirements still awaiting qualification | [THREAT_MODEL.md](../../THREAT_MODEL.md) |
| Private vulnerability reporting, safe harbor, acknowledgement target and a backport policy | [SECURITY.md](../../SECURITY.md) |
| Signed releases with provenance and an SBOM, and commands anyone can run to verify them | [Verify a release](../verify.md), [release trust design](../design/release-trust.md) |
| Plugins load only through a trust policy: publisher admission, signature and revocation checks, an exact ABI match, and no extra runtime permission from trust | [Plugin security](../plugins.md#how-plugins-are-secured), [security posture, section 1](1.6.0-security-posture.md) |
| One crate holds `unsafe` code; every other crate forbids it, and the per-crate count is checked in CI | [What CI checks](../ci.md) (`unsafe-count`, `ffi`) |
| Supply-chain checks on every change: `cargo deny` (advisories, bans, licenses, sources), `osv-scanner` and `cargo vet` | [What CI checks](../ci.md) (`supply-chain`) |
| A tamper-evident audit chain with an independent verification recipe | [Audit verification](../audit-verify.md), [security posture, section 3](1.6.0-security-posture.md) |
| Verified TLS by default for every outbound connection, with an explicit, audited setting for the exceptions | [Migration guide: transport security](../migration-1.6.md#transport-security), [security posture, section 4](1.6.0-security-posture.md) |
| A test discipline: a failing test first, then the fix; no weakened assertions; a black-box comparison against the published 1.5.5 binary | [Testing](../testing.md) |
| Published advisories for confirmed vulnerabilities, with a CVE record where one is assigned | [Advisories](advisories/README.md) |

## What is not yet in place

These are listed on the pages above, and repeated here so the list is not read as a claim of more
than exists:

- Coverage, Miri and fuzzing run as reporting jobs that gate nothing yet; no sanitizer runs over the
  one crate that holds `unsafe` code.
- No paid bug bounty program exists.
- The 1.6.0 security posture records source baselines. It does not assert a final qualification of
  an assembled, published artifact.
