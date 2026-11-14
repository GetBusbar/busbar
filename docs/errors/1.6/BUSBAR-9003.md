---
title: "BUSBAR-9003: Telemetry slot table full (further label sets fall back to the metrics macros)"
description: "What Busbar error BUSBAR-9003 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9003
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

The telemetry bank's pre-registered slot table reached its cap, so further label sets fall back to the ordinary metrics macros instead of a reserved slot — correct, just slower on that path. Warned ONCE per table (a latch), never per registration, so it cannot spam.

## How to fix it

None — self-heals; the fallback path is correct. If a deployment legitimately needs more distinct label sets than the slot cap, that cap is a build-time bound; the metrics remain accurate via the fallback in the meantime.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
