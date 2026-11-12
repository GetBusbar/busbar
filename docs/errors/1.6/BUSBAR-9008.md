---
title: "BUSBAR-9008: Configured worker-thread count is invalid (ignored; default used)"
description: "What Busbar error BUSBAR-9008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9008
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An explicitly-set data-plane worker count — `TOKIO_WORKER_THREADS`/`advanced.worker_threads` — is not a positive integer (e.g. `0`, or non-numeric), so busbar IGNORES it and boots on the default worker count (one per core). The operator's intended worker count is NOT in effect. Emitted pre-tracing, to stderr, at boot.

## How to fix it

Set the data-plane worker count to a positive integer (at least 1) or remove it to accept the default. The gateway runs, but on the default worker count, not the value provided.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
