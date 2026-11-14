---
title: "BUSBAR-2045: Persisted plane per-call record could not be decoded on restore (skipped, not dropped) — RETIRED"
description: "What Busbar error BUSBAR-2045 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2045
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. A principal's persisted plane per-call record could not be decoded at boot — a body from a store format no released build wrote, or a corrupt row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole rehydrate (which would drop every OTHER principal's working set), but the skip is reported here so a silently lost evidence row is never invisible. Usually an engine-version mismatch or a corrupt store.

## How to fix it

Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
