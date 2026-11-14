---
title: "BUSBAR-8109: The admin call failed inside busbar"
description: "What Busbar error BUSBAR-8109 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8109
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An internal failure (a store or plugin error) stopped the call. The response never carries the cause, which may be sensitive; the server log carries it under its own code.

## How to fix it

Check the busbar log at the time of the call for the error line and its code, then retry once the cause is fixed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
