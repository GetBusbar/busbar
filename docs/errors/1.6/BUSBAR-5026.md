---
title: "BUSBAR-5026: Lane hard-down (breaker trip)"
description: "What Busbar error BUSBAR-5026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5026
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, so busbar fails over and stops routing to the lane until its cooldown allows a recovery probe. Recurring still-down probes log at debug. Emitted once per logical trip.

## How to fix it

Traffic fails over automatically. Investigate the named upstream's health if a lane stays hard-down.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
