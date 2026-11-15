---
title: "BUSBAR-5046: Provider usage not read (a unit settled without billing its final stated usage)"
description: "What Busbar error BUSBAR-5046 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5046
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A unit the provider answered settled without billing its final stated usage; `reason` names the ReasonCode that ended it (deadline, drain/reload, unpriced, over-budget, far cut, body cap, plane fault, destination unreachable, client gone before fold). The unit's ledger line bills the last usage report busbar accepted, and its terminal checkpoint record carries the same `unread` reason. Emitted once per affected unit, with an audit row under the same slug.

## How to fix it

Reconcile the line against the provider's usage report: the provider may have charged more than the line bills.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
