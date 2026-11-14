---
title: "BUSBAR-3125: A provider's credential cannot be used as configured"
description: "What Busbar error BUSBAR-3125 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3125
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3125: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3125
```

## What it means

A provider's outbound credential is invalid for its auth style: the referenced secret does not parse (a service-account key, a signing key), required auth settings are missing, or the settings contradict the style. The message names the provider, the style and the secret's source, never its value.

## How to fix it

Fix the secret the message points at (its `env:`, `file:` or module source) or the provider's auth settings, then run `busbar --validate`.

## Example

```text
providers:
  vertex:
    auth: jwt-bearer
    api_key: { env: VERTEX_SA }   # not a service-account JSON
```

Busbar reports:

```text
BUSBAR-3125: provider 'vertex' jwt-bearer credential (from env:VERTEX_SA) is invalid: service-account key is not JSON. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3125
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
