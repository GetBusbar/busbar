---
title: "BUSBAR-4002: Login plugin offload saturated (permit not acquired; login rejected fail-closed)"
description: "What Busbar error BUSBAR-4002 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4002
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A login-plugin call could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — a login plugin is wedged and not returning. busbar rejects the login fail-closed rather than complete a login it never ran. Warned once on entry to the saturated state; recurrence logs at debug.

## How to fix it

Investigate the login plugin (its directory bind or identity-provider round-trip) — it is blocking past its timeout. Restore or restart it; the saturation clears once calls return within budget.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
