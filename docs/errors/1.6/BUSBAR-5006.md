---
title: "BUSBAR-5006: Routing policy deadline exceeded; on_error fallback applied"
description: "What Busbar error BUSBAR-5006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5006
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A routing-policy hook did not answer within the seam's hard wall-clock deadline, so busbar applied the pool's `on_error` fallback. A slow hook adds latency to every request in the pool. Warned once per fault window; continued timeouts log at debug.

## How to fix it

Investigate why the routing-policy hook is slow (overload, blocking I/O, an undersized deadline). Tune the hook or raise its configured timeout if the latency is legitimate.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
