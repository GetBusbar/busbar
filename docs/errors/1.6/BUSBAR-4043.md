---
title: "BUSBAR-4043: Self-serve sign-in or refresh refused: the subject's key is on hold"
description: "What Busbar error BUSBAR-4043 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4043
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A self-serve sign-in (POST /auth/token or the hosted login) or a Refresh was refused because the subject's key is on hold: an administrator disabled it, an administrator revoked it, it was issued through a different identity provider, or the subject itself is held by a principal transition. Nothing is written: the key is not re-enabled, no sibling key is minted, and its old tokens stay dead. The caller gets a 403 that names the reason, and the admin audit log records `self_serve.mint` as `rejected` on `key:<id>#<reason>` (or `subject:<subject>#on_hold`). This is a client-side state, so it is emitted at debug.

## How to fix it

Nothing, if the hold is intended. To let the user back in: for a disabled key, PATCH /api/v1/admin/keys/{id} with `enabled: true` (the same key comes back and its earlier tokens work again). For a revoked key, or a key issued through another provider, DELETE /api/v1/admin/keys/{id}: the next sign-in issues a new key with a new id, and every old token stays dead. A revoked key is never re-enabled.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
