# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/busbar/security/advisories/new)
  (the **Security** tab on the repository).

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
LLM providers. The [threat model](THREAT_MODEL.md) documents the trust boundaries,
assets, and the threats we design against (with pointers to each mitigation in code).
Issues of particular interest include:

- Credential leakage (logs, error bodies, `/stats`, responses relayed to clients).
- Authentication bypass on Busbar's own front-door auth (including timing-based).
- SSRF via a config-controlled upstream (`base_url` / `path` / `path_base` / `token_url`) or a hook `webhook:` URL.
- AWS SigV4 outbound-signing correctness (signed-vs-sent divergence).
- Admin-plane isolation (reaching the control plane from the data port).
- Request smuggling / routing confusion between pools, models, or providers.
- Escape from a dynamically loaded plugin into the host or another plane.
- Denial of service against the gateway or its circuit breaker.
- The circuit breaker mis-attributing a client fault as an upstream fault (or vice
  versa) in a way that drains a pool or leaks state across requests.
- Tampering with an audit chain in a way that is not detected on verification.

Out of scope: deliberately insecure operator configuration that is gated behind an
explicit flag and a boot warning (for example running the admin plane network-exposed
without mutual TLS), and findings that require privileged access to the host or the
backing store the operator already controls.

## Supported versions

Busbar follows a `dev` &rarr; `qa` &rarr; `main` release flow (see [RELEASE.md](RELEASE.md)).
Releases are cut from `main` under a signed version tag. Security fixes are always
developed on `dev` first and flow forward through the normal release process, and, for
higher-severity issues, are backported per the policy below.

| Version line | Supported |
|---|---|
| Latest minor line (current `main` + its most recent tag) | Yes |
| Previous minor line | Yes, for Critical / High backports (see below) |
| Older lines | No; upgrade to a supported line |

Pin to a tag for production use, and verify your download with the recipes at
<https://getbusbar.com/security/>.

## Security backport policy

We turn a security bug into a durable fix rather than a one-off patch. The policy, in two lines:

1. **Fix on `dev` first, always**, with a regression test and, where the class allows, a
   new or tightened CI gate, so the fix retires the class and not just the instance.
2. **Severity-driven backport window.** A **Critical** or **High** fix is cherry-picked to
   the **latest two minor release lines** (for example, from `1.6.x` back to `1.5.x`) on a
   `security/<line>` branch that runs the same `qa` gate before a patch tag. Medium and Low
   issues ride the next normal release.

Every backport carries a GitHub Security Advisory with a requested **CVE** and a `Security`
entry in the [CHANGELOG](CHANGELOG.md), so an operator pinned to a tag can see exactly what
a patch tag fixes. Two lines, rather than more, is the honest commitment for our team size,
and it is a commitment rather than an aspiration.

## Roadmap

We would rather name what is not yet in place than imply it is:

- **Bug bounty:** there is no paid bounty program today. We plan to begin with a published
  safe harbor and a hall of fame (recognition, not cash), then graduate to a funded tier as
  the team grows. Until then, the safe harbor above applies.
- **Dedicated security owner:** security is currently owned by the maintainers. We plan to
  name a dedicated security owner accountable for the disclosure queue and this policy.
