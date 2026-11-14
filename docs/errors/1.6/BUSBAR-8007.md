---
title: "BUSBAR-8007: Group missing at accrual (tokens ledgered to the key bucket only)"
description: "What Busbar error BUSBAR-8007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8007
---

**Area:** Governance & cost (8xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A group referenced by a key was gone by the time usage was accrued (the group was deleted between admission and accrual), so busbar degrades to ledgering the tokens on the key's own bucket only rather than lose them. The request was already admitted and served; nothing is lost. This is a per-request, self-degrading path, so it is emitted at debug.

## How to fix it

None — self-heals; tokens are preserved on the key bucket. Frequent occurrence for one key means a group is being deleted out from under active keys; reconcile the key's group assignment.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
