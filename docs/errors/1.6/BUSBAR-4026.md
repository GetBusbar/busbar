---
title: "BUSBAR-4026: admin_auth chain is EMPTY (it identifies no one; 1.6.0 has no open admin posture)"
description: "What Busbar error BUSBAR-4026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4026
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An EMPTY admin_auth chain was seen. 1.6.0 has no anonymous admin posture: an empty chain identifies no one, so it admits no admin request and earns no scope. Boot and `busbar --validate` refuse `auth.admin_auth: []`, and the live `PUT /api/v1/admin/admin-auth` refuses an empty chain.

## How to fix it

Delete the auth.admin_auth line to use the default chain [<operator>, keys] and set the operator token (identity-providers.<operator>.token), or list the admin providers you use.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
