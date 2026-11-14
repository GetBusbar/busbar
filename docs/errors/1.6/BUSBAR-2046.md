---
title: "BUSBAR-2046: Persisted journal record could not be reframed on restore (skipped, not dropped)"
description: "What Busbar error BUSBAR-2046 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2046
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A scoped journal record could not be reframed at boot — a body from a store format no released build wrote, or a corrupt row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole rehydrate (which would drop every OTHER scope's working set), but the skip is reported here so a silently lost evidence row is never invisible. Usually an engine-version mismatch or a corrupt store.

## How to fix it

Note the scope. If many rows are unreadable, suspect a store format mismatch after an upgrade or downgrade; capture the durable governance store for review.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
