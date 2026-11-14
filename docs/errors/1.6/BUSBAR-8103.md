---
title: "BUSBAR-8103: The admin path does not take this HTTP method"
description: "What Busbar error BUSBAR-8103 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8103
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The path exists on the admin surface, but not with the method the request used (for example a `DELETE` on a read-only collection).

## How to fix it

Use a method the path documents; the OpenAPI document at /docs/api/ lists every path and method.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
