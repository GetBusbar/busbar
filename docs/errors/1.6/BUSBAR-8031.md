---
title: "BUSBAR-8031: A unit checkpoint flush batch was refused whole; smaller batches were used"
description: "What Busbar error BUSBAR-8031 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8031
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The settlement flusher writes finished and running governed units to the store in batches, one write per batch. The store refused a whole batch with no effect (for example a candidate above its size limit) while this writer still held its authority, so the flusher halved the batch size for the rest of that batch of up to 128 items and retried each half. Nothing is lost or written twice. The b field is the batch size it ended with. Logged at most once per batch.

## How to fix it

None if it is rare. If it repeats on every flush, the store's per-write limit is below the flusher's batch of 128 items: raise the store's candidate size limit, or expect settlement to take more round trips.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
