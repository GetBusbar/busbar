---
title: "BUSBAR-3406: Migration widened a retired delegated admin scope to full"
description: "What Busbar error BUSBAR-3406 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3406
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-3406: <entry>: <old> -> full (the delegated <old> scope is retired in 1.5.2; tighten to read-only if full is too broad). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3406
```

## What it means

1.5.2 retired the delegated admin scopes. An auth chain entry or role binding that granted one is migrated to `full`, the nearest scope that keeps every call it allowed working, which may be broader than intended.

## How to fix it

Review the named entry and tighten it to `read-only` if `full` is too broad.

## Example

```text
auth:
  admin_auth:
    - oidc: { max_admin_scope: keys }
```

Busbar reports:

```text
BUSBAR-3406: auth.admin_auth entry 'oidc' max_admin_scope: keys -> full (the delegated keys scope is retired in 1.5.2; tighten to read-only if full is too broad). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3406
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
