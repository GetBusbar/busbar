---
title: "BUSBAR-5044: Unexpected breaker state in record_failure (no-op) — RETIRED"
description: "What Busbar error BUSBAR-5044 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5044
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The breaker failure-recording path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar treats it as a no-op (like the already-Open case) rather than panic the task. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

## How to fix it

Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
