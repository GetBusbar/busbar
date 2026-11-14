---
title: "BUSBAR-3026: Declared billable classes have no configured rate"
description: "What Busbar error BUSBAR-3026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3026
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin declares billable classes for a configured lane, but that lane lacks one or more rates. Startup continues and raw counts remain available. With a present card, missing classes remain unpriced; a rate on another lane does not price them. With no card for the plane, usage-based pricing is disabled. An explicit zero rate is a configured free class, not a missing rate. Class-parent relationships are reporting and cap projections, not inherited prices.

## How to fix it

Configure the named lane and classes in the plane's rate_card. Use an explicit zero only for deliberately free usage. Invalid rates, unknown class names and other structural mistakes still prevent startup.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
