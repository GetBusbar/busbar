---
title: "BUSBAR-4037: A login attempt limiter is disabled"
description: "What Busbar error BUSBAR-4037 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4037
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`auth.login_limits.per_source.enabled` or `auth.login_limits.global.enabled` is false. That is allowed for a site whose WAF already does this, and logged at every boot and reload so it is never silent. The per-account limiter cannot be disabled.

## How to fix it

Re-enable it, or confirm that a WAF in front of busbar rate-limits `POST /auth/token`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
