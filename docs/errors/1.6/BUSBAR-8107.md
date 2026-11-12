---
title: "BUSBAR-8107: The admin request contradicts the server's state"
description: "What Busbar error BUSBAR-8107 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8107
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The request cannot apply to the current state and a retry will not change that: governance is disabled, a base-defined hook cannot be removed, a grant is immutable, a duplicate already exists, or an idempotency key is still in flight. The message says which.

## How to fix it

Change the request (or the state it depends on) as the message describes; this is not a transient error.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
