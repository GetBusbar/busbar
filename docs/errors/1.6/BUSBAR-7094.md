---
title: "BUSBAR-7094: Durable plane demotion record could not be written"
description: "What Busbar error BUSBAR-7094 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7094
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The durable plane demotion record could NOT be written, so this upstream is demoted only in the current process and a restart will re-open it until the next sweep looks again. Usually a durable store-write outage.

## How to fix it

Restore the durable governance store's write path so demotions persist across restarts.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
