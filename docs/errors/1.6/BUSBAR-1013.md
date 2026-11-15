---
title: "BUSBAR-1013: A self-fenced store commit's readback could not decide whether it applied"
description: "What Busbar error BUSBAR-1013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1013
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An administrative commit that can apply at most once lost its reply, and the readback of its witness and predicates could not prove it applied or prove it never will (a record moved past both values, a domain predicate could return to its expected value, or the store refused a predicate that holds). It is held for reconciliation instead of being assumed.

## How to fix it

Reconcile the named administrative step (boot registration, writer transition, first start or migration step) against the store before retrying it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
