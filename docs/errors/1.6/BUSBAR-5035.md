---
title: "BUSBAR-5035: Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)"
description: "What Busbar error BUSBAR-5035 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5035
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), so busbar emits gauges for only the first `limit` keys to bound the exposition's cardinality and scrape-path DB load. Some keys have no per-key series. Warned once until the count drops back under the limit.

## How to fix it

Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can afford the cardinality, or reduce the number of active virtual keys. Aggregate group gauges are unaffected.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
