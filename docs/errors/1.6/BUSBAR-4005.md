---
title: "BUSBAR-4005: Auth chain offload saturated (permit not acquired; request denied fail-closed)"
description: "What Busbar error BUSBAR-4005 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4005
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — an auth plugin is wedged and not returning. The chain never ran, so the credential is unverified and busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

## How to fix it

Investigate the auth plugin — it is blocking past its timeout and starving the offload budget. Restore or restart it; the saturation clears once chain calls return within budget.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
