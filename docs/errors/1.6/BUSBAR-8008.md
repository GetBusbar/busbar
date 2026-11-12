---
title: "BUSBAR-8008: Metering flush: some keys failed to persist this tick (retained for retry)"
description: "What Busbar error BUSBAR-8008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8008
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A metering flush tick could not persist one or more keys' usage deltas to the store. busbar retains the failed deltas and retries them on the next tick, so no usage is lost. This is already collapsed to ONE aggregate warning per tick (per-key detail is at debug), so it fires at a human cadence, not per key.

## How to fix it

Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Usage is retained and re-tried, so billing is not lost, only delayed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
