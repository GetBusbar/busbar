---
title: "BUSBAR-3122: A metadata host list entry can never match"
description: "What Busbar error BUSBAR-3122 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3122
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3122: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3122
```

## What it means

`security.blocked_metadata_hosts` is matched by exact IP or hostname. An entry with a CIDR (`/`) or one that maps to no host would silently never match, leaving the protection it was meant to add a no-op.

## How to fix it

List exact IPs or hostnames, for example `169.254.169.254`, not `169.254.0.0/16`.

## Example

```text
security:
  blocked_metadata_hosts: [169.254.0.0/16]
```

Busbar reports:

```text
BUSBAR-3122: security.blocked_metadata_hosts entry '169.254.0.0/16' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16'). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3122
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
