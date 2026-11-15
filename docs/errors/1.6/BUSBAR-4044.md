---
title: "BUSBAR-4044: Admin request to re-enable a revoked key refused (revoked is terminal)"
description: "What Busbar error BUSBAR-4044 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4044
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A PATCH /api/v1/admin/keys/{id} asked for `enabled: true` on a revoked key. Revoked is terminal: no admin request, sign-in or refresh ever re-enables a revoked key. The request is answered 409 `conflict` with this code, nothing is written, and the admin audit log records `key.patch` as `rejected`. This is a client-side request, so it is emitted at debug.

## How to fix it

Leave the key revoked. To give a self-serve user a working key again, DELETE the revoked key: their next sign-in issues a new key with a new id. For an admin-minted key, mint a new one.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
