---
title: "BUSBAR-8102: The admin request carries no valid admin credential"
description: "What Busbar error BUSBAR-8102 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8102
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The request reached `/api/v1/admin` without a credential the `admin_auth:` chain accepts: no `Authorization: Bearer` header, an unknown or expired token, or a key that is not an admin credential (`invalid_api_key`).

## How to fix it

Send the operator admin token (or a credential your admin auth plugin accepts) in `Authorization: Bearer <token>`. docs/admin-api.md covers the auth chain.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
