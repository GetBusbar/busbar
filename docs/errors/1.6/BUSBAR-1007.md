---
title: "BUSBAR-1007: Admin store blocking task failed to join (cancelled or panicked)"
description: "What Busbar error BUSBAR-1007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1007
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin store operation ran on a `spawn_blocking` task that failed to join — the blocking store closure was cancelled or panicked — so busbar maps it to a generic 500 rather than let a JoinError propagate as an unwrap on the request path. The blocking store closures do not panic in normal operation.

## How to fix it

Investigate the logged operation and store backend — a panic in a blocking store closure is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed, not mis-served.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
