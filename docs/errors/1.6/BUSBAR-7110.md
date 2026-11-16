---
title: "BUSBAR-7110: A plane reported usage for a class it never declared (the usage is dropped)"
description: "What Busbar error BUSBAR-7110 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7110
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane instance reported USAGE (or an expected or observed count) under a billable class its Statement does not declare (`D_USAGE_CLASS`). busbar drops the count: nothing is checkpointed or billed for it, and the unit's other classes are unaffected. Each drop is audited as `plane_usage_undeclared` (verdict `degraded`) under the request's principal, naming the unit and the class.

## How to fix it

Fix the plane to report only classes it declares, or declare the class in the plane's Statement and rebuild it. Until then the dropped usage is not billed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
