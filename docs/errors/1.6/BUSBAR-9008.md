---
title: "BUSBAR-9008: Configured worker-thread count is invalid (ignored; default used)"
description: "What Busbar error BUSBAR-9008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9008
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An explicitly-set data-plane worker count — `TOKIO_WORKER_THREADS`/`advanced.worker_threads` — is out of range or not a positive integer. `0` and non-numeric text are IGNORED and busbar boots on the default worker count (one per core); a count above 65,535, the most the runtime can run, is lowered to 65,535. The operator's intended worker count is NOT in effect. Said once at boot (pre-tracing, to stderr), and in the log when a configuration edit or the recovered document carries such a value; an edit is never refused for it.

## How to fix it

Set the data-plane worker count to an integer from 1 to 65,535 or remove it to accept the default. The gateway runs, but not on the value provided.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
