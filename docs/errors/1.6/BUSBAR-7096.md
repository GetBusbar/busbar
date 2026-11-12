---
title: "BUSBAR-7096: Durable plane demotion records could not be read at boot"
description: "What Busbar error BUSBAR-7096 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7096
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The durable plane demotion records or the operator's trust decisions could NOT be read when a plane instance was admitted, so the instance was refused rather than re-open an upstream this deployment demoted or stand over a revoke it cannot see. Usually a durable store-read outage.

## How to fix it

Restore the durable governance store's read path and restart so persisted demotions are re-applied before a listener binds.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
