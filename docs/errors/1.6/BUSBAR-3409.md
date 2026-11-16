---
title: "BUSBAR-3409: BUSBAR_WORKER_THREADS was not a positive integer and was not captured"
description: "What Busbar error BUSBAR-3409 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3409
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-3409: BUSBAR_WORKER_THREADS is not a positive integer; ignored as in the old launcher; configured workers and the TOKIO_WORKER_THREADS fallback are preserved. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3409
```

## What it means

The migration captures the old launcher's BUSBAR_WORKER_THREADS into `advanced.worker_threads`. Its value was not a positive integer, which the old launcher also ignored, so nothing was captured and the configured worker count (or TOKIO_WORKER_THREADS) still applies.

## How to fix it

Set `advanced.worker_threads` in the migrated config if you meant to pin the worker count, and remove BUSBAR_WORKER_THREADS from the launcher.

## Example

```text
BUSBAR_WORKER_THREADS=auto busbar
```

Busbar reports:

```text
BUSBAR-3409: BUSBAR_WORKER_THREADS is not a positive integer; ignored as in the old launcher; configured workers and the TOKIO_WORKER_THREADS fallback are preserved. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3409
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
