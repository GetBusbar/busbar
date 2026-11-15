---
title: "BUSBAR-1010: Store in-flight queue exhausted: new store writes are refused until slots free up"
description: "What Busbar error BUSBAR-1010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1010
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

Every pending-operation slot of this writer is held, so new store commits answer Overloaded and money-path arrivals are refused with DurabilityUnavailable. Emitted when exhaustion starts and again when it ends, with the in_doubt, resolved_uncollected and reconcile counts of the held slots.

## How to fix it

store unreachable or slow (in_doubt); a domain not collecting answers (resolved_uncollected, a bug); operator reconciliation pending (reconcile). See the busbar_store_slots gauge.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
