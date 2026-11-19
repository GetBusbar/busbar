---
title: "BUSBAR-9008: Configured worker-thread count is invalid — RETIRED"
description: "What Busbar error BUSBAR-9008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9008
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code. The data-plane worker count is no longer a setting: the engine runs one worker per CPU core the process may use (its CPU affinity and container CPU limit). A configuration carrying `advanced.worker_threads`, or a launcher setting TOKIO_WORKER_THREADS, starts as before and says once that the value is ignored.

## How to fix it

Nothing to do. To run fewer workers, lower the container's CPU limit or the process's CPU affinity.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
