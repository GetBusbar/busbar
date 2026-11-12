---
title: "BUSBAR-5038: Plane breaker tripped (upstream target failing; dispatches fast-fail)"
description: "What Busbar error BUSBAR-5038 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5038
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane target's circuit breaker transitioned Closed→Open because the upstream target is failing, so further dispatches fast-fail until the half-open probe recovers it. Names the specific target (every plane target shares one degenerate lane, so without this the operator would not learn WHICH server is down). Emitted once per logical trip, not per failure.

## How to fix it

Investigate the named plane target's health (the tool, agent, or server it fronts). Traffic to it fast-fails until the breaker's half-open probe finds it healthy again.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
