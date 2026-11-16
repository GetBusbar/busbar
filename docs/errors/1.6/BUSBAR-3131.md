---
title: "BUSBAR-3131: An export sink definition is invalid"
description: "What Busbar error BUSBAR-3131 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3131
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3131: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3131
```

## What it means

An entry under `export:` cannot deliver what it promises: an unknown module, settings the module refuses, a stream or field that does not exist, has no producer or that the module cannot carry, a duplicate, an empty list, a pinned field left out, or `durable: true` that this release does not implement.

## How to fix it

Fix the sink the message names; the message lists the valid streams and fields. The `export` section of docs/configuration.md describes the sinks, and docs/export/busbar.content.v1.schema.json is the content schema.

## Example

```text
export:
  siem:
    module: otlp
    streams: [audit]
```

Busbar reports:

```text
BUSBAR-3131: export.siem.streams: `audit` is NOT a stream — it was a use case, not a data type. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3131
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
