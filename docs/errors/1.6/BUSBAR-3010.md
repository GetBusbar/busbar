---
title: "BUSBAR-3010: Heterogeneous pool (cross-protocol failover may not preserve all features)"
description: "What Busbar error BUSBAR-3010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3010
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A pool's members span more than one upstream protocol, so cross-protocol failover within the pool translates requests and replies via busbar's internal representation (IR) and may not preserve every provider-specific feature. Advisory: the pool is valid and serves, but mixed protocols carry a fidelity caveat.

## How to fix it

None required if intentional. If a feature is being lost across failover, split the pool so each pool is single-protocol, keeping cross-protocol members in a fallback tier rather than the same failover pool.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
