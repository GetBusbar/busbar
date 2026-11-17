---
title: "BUSBAR-8021: An entitlement check named a scope kind its plane did not declare"
description: "What Busbar error BUSBAR-8021 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8021
---

**Area:** Governance & cost (8xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A plane asked whether the unit's principal is entitled to a target whose scope kind is not among the scope kinds the plane's tail declares. The kernel denies access without consulting the principal's grants.

## How to fix it

Declare the scope kind in the plane's tail, or correct the target the plane asks about.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
