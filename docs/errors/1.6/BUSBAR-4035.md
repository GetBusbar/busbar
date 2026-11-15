---
title: "BUSBAR-4035: Login attempt limiter cannot reach the core store (sign-ins refused)"
description: "What Busbar error BUSBAR-4035 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4035
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The per-account limiter keeps its counts in the core store so they hold fleet-wide. The store failed, was absent, or a compare-and-swap could not settle, so busbar fails closed: every credential sign-in answers 503 "Couldn't reach your provider" with Retry-After and the login plugin is not called (a sign-in could not finish anyway: issuing the key writes to the same store). Warned on entering the state and logged on recovery.

## How to fix it

Restore the core store (`store:`). Sign-ins resume on their own once it answers.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
