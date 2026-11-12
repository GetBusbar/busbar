---
title: "BUSBAR-3020: rate_card entry prices a model at ALL ZERO (metered as free, uncapped)"
description: "What Busbar error BUSBAR-3020 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3020
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A model has a `rate_card` entry present but every tier (input, output, cache_read, cache_write) is zero, so its token usage prices to $0: budget-group `budget:` limits never accrue token cost against it and it is effectively uncapped on spend. This is LEGAL (a deliberately free model is a valid choice, e.g. a self-hosted lane), so it is a WARNING, not a boot error — but an accidental all-zero entry (a paste of the completeness stub left unfilled) silently under-bills every request to that model.

## How to fix it

If the model is intentionally free, ignore this. Otherwise fill in the model's `rate_card` rates (micro-units per token) so its usage prices and counts against any `budget:` limit.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
