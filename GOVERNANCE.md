# Project governance

<!-- Source: DES-docs-policy r3 (adopted; #179 items 7-9, #175 item 1) with the PM's provisional
     answers applied as the design records. Key custody is not described here: see docs/verify.md. -->

Busbar is maintained by one person, Matthew Jackson. This page records how the project is run
today. It describes practice, not aspiration: where something is missing, it says so.

## Roles

| Role | Who | Responsibility |
|---|---|---|
| Maintainer | Matthew Jackson | Sets scope, makes design rulings, merges, promotes `dev` to `qa` and `main`, signs and publishes releases, administers access, and rotates signing keys. |
| Security contact | Matthew Jackson | Receives private reports through the channels in [SECURITY.md](SECURITY.md), coordinates the fix and files the GitHub Security Advisory. |
| Contributor | Anyone | Reports problems, proposes designs and submits changes under [CONTRIBUTING.md](CONTRIBUTING.md). A contribution gives no repository, release or signing access. |

The **bus factor is 1.** No second person can merge, cut a release, rotate a signing key or read
the private report queue today. Automation that acts under the maintainer's delegated access is not
a second maintainer.

## How decisions are made

- **Design first.** A change to behavior, architecture, the plugin ABI or dependencies starts as a
  written design: the problem, the intended behavior, compatibility and failure cases. The design
  is reviewed by two independent reviewers before it is built. Documentation, mechanical changes
  and the application of an already adopted design need no new design.
- **Recorded rulings.** The maintainer resolves open questions and disagreements. Each ruling is
  recorded in the project's ruling register, and the change that applies it cites the ruling or
  the issue.
- **Owner approval on guarded files.** Changes to CI configuration and to the files listed in
  [CODEOWNERS](.gitlab/CODEOWNERS) need the maintainer's approval.
- **One source of truth.** Development happens on the project's GitLab; the
  [GitHub repository](https://github.com/GetBusbar/busbar) is a read-only mirror of it. The one
  write on the mirror is security-advisory metadata: the maintainer files GitHub Security
  Advisories there. Code never changes on the mirror.

Security reports stay private while a fix is coordinated; see [SECURITY.md](SECURITY.md).

## Access and continuity

The maintainer holds every administrative account, the release and plugin signing authority, and
the means to recover them. Signing-key rotation is the maintainer's alone. The verification
procedure for released artifacts is in [docs/verify.md](docs/verify.md); this page does not
describe key custody or the location of recovery material, and this repository contains no
recovery secrets.

There is no successor today. If the maintainer is unavailable, the public source, its history and
the published releases remain available, but nobody else can merge, publish, sign or receive
security reports. Do not bypass a signature check or a protected branch to work around that
absence.

## Adding a maintainer

A second maintainer is added on the maintainer's nomination, after sustained merged contributions
over at least 6 months. Nothing on this page appoints anyone.

See also [contributing](CONTRIBUTING.md), [releasing](RELEASE.md) and the
[security policy](SECURITY.md).
