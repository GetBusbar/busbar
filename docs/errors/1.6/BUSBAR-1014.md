---
title: "BUSBAR-1014: The store answered an inconsistent time-guard failure"
description: "What Busbar error BUSBAR-1014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1014
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The store reported a time-guard failure whose observation came from another clock authority, or whose time the commit's guard permits, or for a commit with no guard. That is a store fault; retrying would replay the same recorded verdict, so the operation is held for reconciliation.

## How to fix it

Check the store plugin and its clock authority. Capture the log line (store, writer, slot, observed authority and time, the guard) and reconcile the held operation.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
