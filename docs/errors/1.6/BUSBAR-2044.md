---
title: "BUSBAR-2044: Admin audit record could not be written through the durable journal seam (evidence lost)"
description: "What Busbar error BUSBAR-2044 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2044
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin audit record could NOT be written through the durable journal seam, so this mutation is being served but its evidence is being lost on that path. The chain position is unchanged, so the chain stays contiguous — what is missing is this one record, not the ones after it. This can recur per mutation during a store outage, so it warns on the transition into the failing state and holds subsequent occurrences at debug.

## How to fix it

Restore the durable governance store's write path. Once writes succeed again the latch resets and a future outage re-warns.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
