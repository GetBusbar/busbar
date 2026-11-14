---
title: "BUSBAR-8005: Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed)"
description: "What Busbar error BUSBAR-8005 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8005
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

During a self-serve key refresh, tombstoning the prior binding failed and the compensating rollback of the newly-minted binding ALSO failed, so the subject may now have TWO live bindings in the store for one identity. busbar exhausted its best-effort recovery and surfaces the inconsistent state for inspection. Rare.

## How to fix it

Inspect the governance store for the named subject — it may hold two live bindings (old_id and new_id). Tombstone whichever is not intended so the subject has exactly one valid credential.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
