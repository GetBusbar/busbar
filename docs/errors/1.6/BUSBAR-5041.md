---
title: "BUSBAR-5041: Unexpected breaker state on classify (fail-safe: deny admission) — RETIRED"
description: "What Busbar error BUSBAR-5041 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5041
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The breaker classify path read a cell state that is not one of the three valid encodings (Closed/Open/HalfOpen). This is IMPOSSIBLE under the atomic-sentinel invariant, so reaching it means a real invariant break or memory corruption. busbar fails SAFE — treats the cell as never-elapsing Open so admission is denied — rather than panic the dispatching task. Warned once per process; recurrence logs at debug.

## How to fix it

Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
