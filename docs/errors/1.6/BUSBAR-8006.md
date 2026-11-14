---
title: "BUSBAR-8006: Self-serve refresh: cache reconcile failed after tombstoning the prior binding"
description: "What Busbar error BUSBAR-8006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8006
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

During a self-serve key refresh, the store tombstone of the prior binding committed but the follow-up cache reconcile (a store round-trip) failed. busbar evicted the prior binding directly from the cache so its old token stops verifying immediately; the store is consistent, but the rest of the cache may be stale until the next successful refresh.

## How to fix it

Investigate the governance store's reachability — the durable state is correct and the old credential no longer verifies. The cache self-heals on the next successful reconcile; sustained failures mean the store is unhealthy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
