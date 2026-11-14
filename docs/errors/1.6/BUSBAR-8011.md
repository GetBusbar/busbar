---
title: "BUSBAR-8011: Budget flush: some buckets failed to persist this tick (re-marked dirty for retry)"
description: "What Busbar error BUSBAR-8011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8011
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A budget flush tick could not persist one or more group-budget buckets to the store. busbar re-marks those buckets dirty and retries them on the next tick, so no spend is lost. This is already collapsed to ONE aggregate warning per tick (per-bucket detail is at debug), so it fires at a human cadence, not per bucket.

## How to fix it

Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Spend is retained and re-tried, so budgets are not lost, only delayed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
