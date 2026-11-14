---
title: "BUSBAR-3120: The store block is missing or names no module"
description: "What Busbar error BUSBAR-3120 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3120
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3120: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3120
```

## What it means

Busbar keeps keys, budgets, audit and configuration overlays in the store named by top-level `store:`. The block is missing or its `module:` is empty.

## How to fix it

Add `store: { module: <store plugin> }` (for example `sqlite` with a `db_path` setting).

## Example

```text
store:
  module: ""
```

Busbar reports:

```text
BUSBAR-3120: store.module must be non-empty; name the configured Store plugin. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3120
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
