---
title: "BUSBAR-7111: A plane reported usage with a scale past micro-units (the quantity is rounded)"
description: "What Busbar error BUSBAR-7111 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7111
---

**Area:** Plane protocols (7xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A plane instance reported USAGE with a scale above 6. The ledger counts in micro-units, so busbar rounded the quantity half-even to six decimal places before checkpointing or billing it. Each rounding is audited as `plane_usage_rounded` (verdict `degraded`) under the request's principal, naming the unit and the class.

## How to fix it

None needed for a plane that reports at most nine decimal places and tolerates micro-unit rounding. If the rounding matters, have the plane report in a coarser unit so the quantity fits six decimal places.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
