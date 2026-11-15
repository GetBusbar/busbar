---
title: "BUSBAR-1012: A live store commit was answered STALE: the slot queue invariant was broken"
description: "What Busbar error BUSBAR-1012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1012
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The store reported that a later sequence of this commit's slot was already evaluated. A live attempt holds its slot, so this means the slot was leased twice or the store's slot row is wrong. Nothing was applied by this send; an in-doubt attempt is held for reconciliation.

## How to fix it

This is a bug in the slot facade or the store plugin. Capture the log line (writer, slot) and file a bug; reconcile any held operation.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
