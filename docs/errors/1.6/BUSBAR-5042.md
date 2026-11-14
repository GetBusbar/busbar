---
title: "BUSBAR-5042: Unexpected breaker state on probe acquisition (fail-safe: refuse) — RETIRED"
description: "What Busbar error BUSBAR-5042 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5042
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The breaker probe-acquisition path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar refuses the probe acquisition (admits nobody) rather than panic the dispatching task. Same invariant-break family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

## How to fix it

Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
