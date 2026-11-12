---
title: "BUSBAR-5033: Could not spawn the metrics maintenance thread (observations drain on scrape only)"
description: "What Busbar error BUSBAR-5033 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5033
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered metric observations now drain only when /metrics is scraped instead of on a timer. Metrics are still correct but may lag between scrapes.

## How to fix it

Investigate the thread-spawn failure (typically OS thread/resource exhaustion). Metrics remain available on scrape; restart after resolving the resource limit for timely draining.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
