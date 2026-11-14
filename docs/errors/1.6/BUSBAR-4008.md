---
title: "BUSBAR-4008: Admin auth offload saturated (permit not acquired; request denied fail-closed)"
description: "What Busbar error BUSBAR-4008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4008
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin auth chain could not obtain a blocking-offload permit within the wait window because the admin offload budget is fully in flight — an admin auth plugin is wedged and not returning. The chain never ran, so busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

## How to fix it

Investigate the admin auth plugin — it is blocking past its timeout. Restore or restart it; admin access is denied until admin-chain calls return within budget.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
