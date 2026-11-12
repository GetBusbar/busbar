---
title: "BUSBAR-8104: The admin credential's scope does not cover this call"
description: "What Busbar error BUSBAR-8104 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8104
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The caller authenticated, but its admin scope (read-only, or a role binding's verb list) does not include this operation. The message names the scope that would have sufficed.

## How to fix it

Call with a credential whose scope covers the operation, or widen the role binding's `admin_scope` or `verbs`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
