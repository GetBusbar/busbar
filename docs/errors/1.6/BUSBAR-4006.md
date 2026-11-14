---
title: "BUSBAR-4006: Auth chain panicked (request denied fail-closed)"
description: "What Busbar error BUSBAR-4006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4006
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain's blocking task panicked, so busbar denies the request fail-closed rather than admit an unverified credential. A panicking chain is a plugin bug. Warned once on entry to the panicking state; recurrence logs at debug.

## How to fix it

Fix the auth plugin — a panic in the chain is a bug in one of its modules. Capture the logged error and the plugin's own logs; requests are denied until it is corrected.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
