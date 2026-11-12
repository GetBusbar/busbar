---
title: "BUSBAR-1009: Admin /usage blocking task failed to join (cancelled or panicked)"
description: "What Busbar error BUSBAR-1009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1009
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin /usage read ran on a `spawn_blocking` task that failed to join (cancelled or panicked), so busbar answers the request with a generic 500. Distinct from a store error returned by the read itself (BUSBAR-1006): here the blocking task did not complete at all.

## How to fix it

Investigate the logged context and store backend — a blocking-task panic is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
