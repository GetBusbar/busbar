---
title: "BUSBAR-8009: delete_key: tombstone committed and key evicted, but cache reconcile failed"
description: "What Busbar error BUSBAR-8009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8009
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin key deletion committed the tombstone in the store and evicted the deleted key from the in-memory caches (it no longer authenticates), but the follow-up full cache reconcile failed. The deletion is durable and the key is dead; only OTHER cache entries may be stale until the next successful refresh. Rare admin path.

## How to fix it

Investigate the governance store's reachability — the deletion itself is complete and safe. The cache self-heals on the next successful refresh; sustained failures indicate an unhealthy store.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
