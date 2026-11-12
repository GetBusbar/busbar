---
title: "BUSBAR-5043: Unexpected breaker state on state read (reporting Closed) — RETIRED"
description: "What Busbar error BUSBAR-5043 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5043
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. A breaker cell state read (a total, side-effect-free projection) found an unexpected encoding. Impossible under the atomic-sentinel invariant; busbar reports the benign Closed default rather than panic, keeping the read total for any encoding. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

## How to fix it

Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
