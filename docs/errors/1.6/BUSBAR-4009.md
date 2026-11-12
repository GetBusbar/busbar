---
title: "BUSBAR-4009: Admin auth chain did not complete in time (request denied fail-closed)"
description: "What Busbar error BUSBAR-4009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4009
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin auth chain's offloaded task did not complete within its deadline, or it panicked, so busbar denies the admin request fail-closed rather than admit an unverified operator. Warned once on entry to the stalled state; recurrence logs at debug.

## How to fix it

Investigate the admin auth plugin — it is slow or crashing on the admin path. Restore or restart it; admin access is denied until the chain completes within its deadline.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
