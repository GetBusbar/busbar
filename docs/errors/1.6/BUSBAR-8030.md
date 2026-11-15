---
title: "BUSBAR-8030: Governed admission paused (draining, or finished requests await settlement)"
description: "What Busbar error BUSBAR-8030 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8030
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

New governed requests are refused with a 503: either the gateway is shutting down (cause=drain, reason drain, retry on another instance) or the number of finished governed requests whose spend still awaits settlement in the store reached its cap (cause=custody_full, reason durability_unavailable, Retry-After 1). Running requests and streams are never refused, and every refusal is audited on its unit. Logged once per episode; an Info line follows when the backlog falls below 90% of the cap.

## How to fix it

For custody_full, check the store's latency and throughput: settlement is slower than governed arrival. For drain, route traffic to another instance until this one restarts.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
