---
title: "BUSBAR-9016: First start step slower than its budget (waiters may take over)"
description: "What Busbar error BUSBAR-9016 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9016
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A first-start owner went longer than the step budget (45 s, plus 35 s for a step that runs inside a plane's READY) between two progress writes. Waiting replicas take over after 90 s without progress, so a gap near that window risks retiring a live owner. The line names the step and the gap.

## How to fix it

Find what made the step slow (plugin load or open, driver build, the store, an import page) and make it faster. A single replica is not at risk; several replicas sharing the store are.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
