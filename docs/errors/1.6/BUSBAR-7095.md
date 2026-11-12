---
title: "BUSBAR-7095: Durable plane demotion record could not be cleared"
description: "What Busbar error BUSBAR-7095 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7095
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The durable plane demotion record for an upstream could NOT be cleared even though it is serving again in the current process, so a restart would re-establish a quarantine the operator has already worked. Usually a durable store-write outage.

## How to fix it

Restore the durable governance store's write path so a cleared demotion does not reappear after a restart.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
