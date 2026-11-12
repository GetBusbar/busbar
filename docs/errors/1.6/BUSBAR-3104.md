---
title: "BUSBAR-3104: A pool shares its name with a provider or a model"
description: "What Busbar error BUSBAR-3104 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3104
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3104: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3104
```

## What it means

Pools, providers and models share one route namespace (`/<name>/...`), so a pool may not take the name of a provider or a model: one of the two would be unreachable.

## How to fix it

Rename the pool (or the provider or model) so every name is distinct, and update the references to it.

## Example

```text
models:
  fast: { provider: openai }
pools:
  fast: { members: [fast] }
```

Busbar reports:

```text
BUSBAR-3104: pool name 'fast' conflicts with model name 'fast'; pools and models must have distinct names. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3104
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
