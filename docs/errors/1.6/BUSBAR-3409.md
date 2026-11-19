---
title: "BUSBAR-3409: BUSBAR_WORKER_THREADS was not a positive integer and was not captured — RETIRED"
description: "What Busbar error BUSBAR-3409 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3409
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code. The worker count is no longer a setting, so the migration captures nothing from BUSBAR_WORKER_THREADS: the engine runs one worker per CPU core the process may use. A launcher that still sets the variable starts and says once that it is ignored (BUSBAR-3029).

## How to fix it

Remove BUSBAR_WORKER_THREADS from the launcher when convenient.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
