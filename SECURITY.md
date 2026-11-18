# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/busbar/security/advisories/new)
  (the **Security** tab on the repository).

The **security contact** for this project is the Busbar maintainer, **Matthew Jackson**, who owns
the disclosure queue and this policy and monitors **security@getbusbar.com**.

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/busbar/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

### CVE identifiers and disclosure

<!-- Source: DES-docs-policy r3 (adopted) §2 items 1-5, PM provisional answers applied. -->

- **Who assigns.** The maintainer decides whether a confirmed vulnerability gets a CVE: one in a
  released version that has been or will be publicly disclosed. The CVE is requested through a
  GitHub Security Advisory, with GitHub as the CVE Numbering Authority. The reporter is told the
  CVE identifier as soon as it is assigned.
- **Timeline.** The embargo is agreed with the reporter for each report. The advisory is published
  when the fix ships, and the CVE Record is published within 72 hours of public disclosure. Beyond
  that and the 48-hour acknowledgement above, the project makes no numeric response commitment.
- **End-of-life lines.** A vulnerability in a line past its support date (see
  [supported versions](#supported-versions)) gets a CVE only when it is confirmed on that line, and
  the record is tagged "unsupported when assigned".
- **Disputes.** To contest a severity or an assignment decision, write to
  **security@getbusbar.com**. A dispute that stays unresolved can be taken to the CNA (GitHub) or to
  the CVE Program.
- **Backup contact.** There is none today: the bus factor is 1 (see [GOVERNANCE.md](GOVERNANCE.md)).
- **Advisories.** Each published advisory in [docs/security/advisories/](docs/security/advisories/)
  lists its CVE identifiers once they are assigned.

### Safe harbor

We support good-faith security research. If you make a genuine effort to comply with this
policy while investigating an issue, we will consider your research authorized, we will not
pursue or support legal action against you for it, and we will work with you to understand
and resolve the issue quickly. Good faith means: you report privately through the channels
above and give us a reasonable time to remediate before any disclosure; you only interact
with accounts and systems you own or have explicit permission to test; you do not access,
modify, delete, or exfiltrate data that is not yours; and you avoid privacy violations,
service degradation, and data destruction. This authorization covers your research activity
only; it is not a waiver of any third party's rights, and it does not authorize testing
against systems operated by our users or other parties.

## Scope

Busbar holds provider credentials centrally and acts as the front door to upstream
services through configured plane plugins. The [threat model](THREAT_MODEL.md) documents the trust
boundaries, assets, implementation limits and requirements still awaiting release qualification.
1.6.0 is in active development; source and tests are not evidence that a final deployment or
published artifact has passed qualification. The [security posture](docs/security/1.6.0-security-posture.md)
records the source baseline for its implementation claims.
Issues of particular interest include:

- Credential leakage (logs, error bodies, `/stats`, responses relayed to clients, the store).
- Authentication bypass on Busbar's own front-door auth (including timing-based), or reaching an
  admin-scoped operation with a read-only credential.
- SSRF via a configured or request-derived destination (`base_url` / `path` / `path_base` /
  `token_url`, a tool server, agent or export URL, a plugin fetch URL), including a way past the
  connector's destination guard (DNS rebinding, alternate address spellings).
- AWS SigV4 outbound-signing correctness (signed-vs-sent divergence).
- Admin-plane isolation (reaching the control plane from the data port).
- Request smuggling / routing confusion between pools, models, or providers.
- Loading a plugin the trust policy should refuse: unsigned or unknown-publisher code without the
  explicit `plugins.trust.allow_untrusted` opt-in, an invalid known-publisher signature, a revoked
  key, an out-of-scope plugin name, a tampered tarball, an older build below its version floor, or
  bytes other than the ones verified. Trusted publisher admission must not require a separate
  third-party switch or grant additional runtime permissions.
- A plugin reaching, through the plugin ABI, kernel state or another plane's state it was not
  granted.
- A plugin obtaining, through the ABI, a credential it was not configured with, or a host path that
  prints, logs, serializes or sends to the wrong host a credential a plugin was configured with. (In
  1.6.0 a plugin receives the credentials it is configured with, and native code can read Busbar's
  own process memory; see [threat model T9 and T10](THREAT_MODEL.md).)
- Calling an MCP tool or A2A agent whose advertised definition differs from the one approved
  (a way around verify-on-call; see [tool and agent trust](docs/tool-and-agent-trust.md)).
- Denial of service against the gateway or its circuit breaker.
- The circuit breaker mis-attributing a client fault as an upstream fault (or vice
  versa) in a way that drains a pool or leaks state across requests.
- Tampering with an audit chain in a way that is not detected on verification.
- Reporting unverified or unsealed audit data as verified, reporting ephemeral Store state as
  crash-durable, or bypassing a configured TLS requirement or its scoped acceptance policy.

Out of scope: deliberately insecure operator configuration that is gated behind an
explicit flag and a boot warning (for example running the admin plane network-exposed
without mutual TLS). Bypassing the scope of an opt-in, suppressing its required evidence, or
misrepresenting untrusted code as verified remains in scope. Findings that require privileged
access to the host or the backing store the operator already controls are out of scope.

## Supported versions

Busbar follows a `dev` &rarr; `qa` &rarr; `main` release flow (see [RELEASE.md](RELEASE.md)).
Releases are cut from `main` under a signed version tag. Security fixes are always
developed on `dev` first and flow forward through the normal release process, and they
reach every supported line per the policy below.

| Version line | Supported |
|---|---|
| A minor line `x.y` | Security fixes until the later of 12 months after `x.y.0` or 6 months after the next `x.y.0` |
| A line past that date | End of life; upgrade to a supported line |

Supported today, with dates taken from the release tags:

- **1.6.x**: from its release.
- **1.5.x** (`v1.5.0`, 2026-08-01): until the later of 2027-08-01 and 6 months after `v1.6.0`.
- **1.4.x** (`v1.4.0`, 2026-07-19): until 2027-07-19.

Pin to a tag for production use, and verify your download with the recipes at
<https://getbusbar.com/security/>.

## Security backport policy

We turn a security bug into a durable fix rather than a one-off patch. The policy, in two lines:

1. **Fix on `dev` first, always**, with a regression test and, where the class allows, a
   new or tightened CI gate, so the fix retires the class and not just the instance.
2. **Every supported line.** A fix reaches every supported line (above). How a fix is cut
   for an older line is set out in [RELEASE.md](RELEASE.md).

Every backport carries a GitHub Security Advisory with a requested **CVE** and a `Security`
entry in the [CHANGELOG](CHANGELOG.md), so an operator pinned to a tag can see exactly what
a patch tag fixes.

## Roadmap

We would rather name what is not yet in place than imply it is:

- **Bug bounty:** there is no paid bounty program today. We plan to begin with a published
  safe harbor and a hall of fame (recognition, not cash), then graduate to a funded tier as
  the team grows. Until then, the safe harbor above applies.
- **Security owner:** the disclosure queue and this policy are owned by the project maintainer
  (**Matthew Jackson**, `security@getbusbar.com`), named above. As a solo-maintained project the
  **bus factor is 1**; broadening ownership is a growth item we name rather than imply.
