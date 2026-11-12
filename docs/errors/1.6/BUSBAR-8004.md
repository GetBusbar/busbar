---
title: "BUSBAR-8004: Unrecognized limit window (enforcing as all-time 'total')"
description: "What Busbar error BUSBAR-8004 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8004
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A limit's window word was not recognized — it can only arise from a corrupt or foreign store row, since config parse rejects unknown windows. busbar fails SAFE and enforces the limit as the all-time ('total') window, the tightest enforcement, never wider, and surfaces the value so the corruption is visible instead of silent.

## How to fix it

Inspect the governance store row for the named window value — it was written by something other than a validated config load. Enforcement is safe (all-time) in the meantime; correct the row so the intended window applies.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
