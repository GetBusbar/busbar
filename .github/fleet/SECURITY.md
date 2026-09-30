# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/@@repo@@/security/advisories/new)
  (the **Security** tab on this repository).

Please include a description of the issue and its impact, steps to reproduce (a
proof of concept if available), the affected version or commit, and any suggested
mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/@@repo@@/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish
to be credited once a fix is released.

## Scope

`@@repo@@` is a `kind: @@kind@@` busbar plugin. Its README states what it does and
its documented limitations. See busbar's own
[threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md) for the
trust boundaries every plugin operates inside.

## Supported versions

Security fixes are applied to the latest `main` and the most recent tagged release
of **this repository**. Pin to a tag for production use.
