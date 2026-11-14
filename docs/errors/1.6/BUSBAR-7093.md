---
title: "BUSBAR-7093: Durable plane per-call record could not be written (evidence lost) — RETIRED"
description: "What Busbar error BUSBAR-7093 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7093
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The durable plane per-call record could NOT be written, so this call is being served but its evidence is being lost. The chain position is unchanged, so the chain stays contiguous — what is missing is this one record, not the ones after it. This can recur per request during a store outage, so it warns on the transition into the failing state and holds subsequent occurrences at debug.

## How to fix it

Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
