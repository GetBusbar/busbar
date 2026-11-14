---
title: "BUSBAR-8022: A unit reported a usage class its plane never declared (the line is refused, not billed)"
description: "What Busbar error BUSBAR-8022 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8022
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A unit's drained usage report named a class that no installed plane declares as billable, no configured `units:` entry names, and is not one of the reserved four. The unit's one line is still written with every count, but its money is REFUSED rather than priced: a class nobody declared is never billed at zero and never dropped. Every read of the balance the line sits on refuses until it is explained.

## How to fix it

The plane that served the unit reported a class outside its declaration, which is a plugin defect: upgrade or fix the plane so it declares every class it reports, or configure the class under the lane's `units:` if it is an operator-priced open class.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
