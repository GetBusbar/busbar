---
title: "BUSBAR-5036: Metrics scrape: usage read failed; skipping key"
description: "What Busbar error BUSBAR-5036 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5036
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

During a /metrics scrape, reading one virtual key's usage from the store failed, so busbar skips that key's gauges for this scrape and continues with the rest. Per-key, per-scrape.

## How to fix it

None — self-heals on the next scrape. A high volume across keys points to a governance-store problem.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
