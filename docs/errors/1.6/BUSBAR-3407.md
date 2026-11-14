---
title: "BUSBAR-3407: An empty allowed_pools list now means no pools"
description: "What Busbar error BUSBAR-3407 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3407
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-3407: auth.role_bindings.<module>.<role>.allowed_pools: [] - the MEANING of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now means NO pools. If this role should reach every pool, DELETE the allowed_pools line (omitted = all); if it should reach none, keep []. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3407
```

## What it means

Before 1.5.0 an empty `allowed_pools: []` on a role binding meant every pool; since 1.5.0 it means no pool. The migration keeps the list as written, so the role now reaches nothing.

## How to fix it

If the role should reach every pool, delete the `allowed_pools` line (omitted means all). If it should reach none, keep `[]`.

## Example

```text
auth:
  role_bindings:
    oidc:
      engineers: { allowed_pools: [] }
```

Busbar reports:

```text
BUSBAR-3407: auth.role_bindings.oidc.engineers.allowed_pools: [] - the MEANING of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now means NO pools. If this role should reach every pool, DELETE the allowed_pools line (omitted = all); if it should reach none, keep []. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3407
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
