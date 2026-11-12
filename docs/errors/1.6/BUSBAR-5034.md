---
title: "BUSBAR-5034: Metrics scrape: failed to list virtual keys (per-key gauges skipped)"
description: "What Busbar error BUSBAR-5034 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5034
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A /metrics scrape could not list virtual keys from the governance store (a transient store hiccup), so it skips the per-key spend/token gauges for this scrape. Other gauges still refresh.

## How to fix it

None — self-heals on the next scrape once the store responds. Sustained failures indicate a governance-store problem worth investigating.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
