---
title: "BUSBAR-3408: Migration added a binding that keeps 1.5.5's ungoverned access"
description: "What Busbar error BUSBAR-3408 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3408
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-3408: auth.role_bindings.<provider>."<role>" was written by the migration to keep 1.5.5's access: <who> is admitted on every pool with no budget, as 1.5.5 admitted them. Tighten it (allowed_pools, a group with limits) or remove it to refuse them. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3408
```

## What it means

1.5.5 admitted a principal its identity provider recognised even when no role binding granted it anything; 1.6.0 refuses such a principal (401). To keep a migrated deployment serving the same callers, the migration wrote an empty binding for them: every pool, no group, no budget.

## How to fix it

Tighten the named binding (allowed_pools, a group with limits) or remove it to refuse those principals.

## Example

```text
auth:
  auth_chain: [oidc]
```

Busbar reports:

```text
BUSBAR-3408: auth.role_bindings.oidc."*" was written by the migration to keep 1.5.5's access: every principal it identifies is admitted on every pool with no budget, as 1.5.5 admitted them. Tighten it (allowed_pools, a group with limits) or remove it to refuse them. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3408
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
