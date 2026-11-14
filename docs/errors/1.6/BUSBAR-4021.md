---
title: "BUSBAR-4021: Anomaly breaker suspended a trust registration — RETIRED"
description: "What Busbar error BUSBAR-4021 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4021
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: no anomaly breaker suspends a trust registration. The one breaker that was to raise it was never armed (no configuration set its thresholds) and is deleted, so a registration stops serving only on a drift or an operator's suspension.

## How to fix it

Nothing emits this code.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
