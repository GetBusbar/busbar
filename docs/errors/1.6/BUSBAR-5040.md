---
title: "BUSBAR-5040: Lane hard-down across all cells (sticky cooldown; recovers via half-open probe)"
description: "What Busbar error BUSBAR-5040 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5040
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A lane was recorded hard-down across ALL its per-pool cells at once (the all-cells variant of BUSBAR-5026) — every pool's view of the lane is tripped Open with a sticky cooldown. The lane is RECOVERABLE via the half-open probe (it is not marked dead), so it re-admits once a probe succeeds.

## How to fix it

Investigate the named upstream/model lane's health — a hard-down across all cells means a definitive lane-wide fault. Traffic fails over automatically; the lane recovers via the half-open probe once the upstream is healthy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
