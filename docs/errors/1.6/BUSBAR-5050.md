---
title: "BUSBAR-5050: Routing policy made no choice and no member has a known routing cost"
description: "What Busbar error BUSBAR-5050 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5050
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The pool's ordering policy made no choice and no member has a known routing cost; the pool uses weighted round-robin. Gates never report this. Warned once per policy and pool until the policy ranks that pool again.

## How to fix it

If the policy ranks by cost, price every member's lane in rate_card; a named hook also needs `signals: [candidate_route_cost]`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
