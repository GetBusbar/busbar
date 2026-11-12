---
title: "BUSBAR-5037: Metrics scrape: group ledger read failed; skipping bucket"
description: "What Busbar error BUSBAR-5037 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5037
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

During a /metrics scrape, reading a group budget bucket's ledger from the store failed, so busbar skips that bucket's gauges for this scrape and continues. Per-bucket, per-scrape.

## How to fix it

None — self-heals on the next scrape. Sustained failures indicate a governance-store problem.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
