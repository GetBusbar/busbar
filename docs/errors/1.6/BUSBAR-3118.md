---
title: "BUSBAR-3118: A rate card or fee is invalid"
description: "What Busbar error BUSBAR-3118 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3118
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3118: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3118
```

## What it means

A rate card or fee cannot be priced as written: a rate that is negative, not finite or implausibly large, a unit or class the plane does not declare or count, a reserved class priced by name, a card entry for a model that is not defined, or a negative per-request fee.

## How to fix it

Fix the named entry: price only the units and classes the plane declares, keep rates finite and non-negative, and name only defined models.

## Example

```text
rate_card:
  gpt-5: { input_utok: 1.25 }   # no model gpt-5
```

Busbar reports:

```text
BUSBAR-3118: rate_card names model 'gpt-5', which is not defined under models:. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3118
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
