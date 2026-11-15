---
title: "BUSBAR-1011: A store commit whose earlier send may have applied was fenced on retry"
description: "What Busbar error BUSBAR-1011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1011
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A slotted commit lost its reply, and its retry found the writer's epoch no longer admitted (the writer was closed, which also deleted its slot rows). Whether the earlier send applied cannot be decided automatically, so the operation is held for reconciliation instead of being assumed either way.

## How to fix it

Reconcile the named operation against the store's records before reusing its effects. This follows a writer closure (recovery adoption or shutdown) while a commit was in doubt.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
