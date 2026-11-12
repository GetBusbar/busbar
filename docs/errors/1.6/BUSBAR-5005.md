---
title: "BUSBAR-5005: Routing policy failed; on_error fallback applied"
description: "What Busbar error BUSBAR-5005 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5005
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A routing-policy hook returned an ERROR while deciding a request, so busbar applied the pool's configured `on_error` fallback. A hook binary that is down, crashing, or returning garbage degrades every request in the pool to the fallback. Warned once per fault window; continued failures log at debug.

## How to fix it

Fix the routing-policy hook — check that its process is running, reachable, and returning a valid decision. The pool serves via `on_error` until it recovers.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
