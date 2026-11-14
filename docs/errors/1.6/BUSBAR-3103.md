---
title: "BUSBAR-3103: A model, pool or provider is named after a reserved route prefix"
description: "What Busbar error BUSBAR-3103 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3103
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3103: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3103
```

## What it means

Models, pools and providers are reachable at `/<name>/...`. The names `admin` and the native-API root are routed to the operator admin surface before any model, pool or provider route, so an entry with one of those names could never be reached by a client and would bypass its own governance.

## How to fix it

Rename the model, pool or provider the message names, and update every reference to it.

## Example

```text
pools:
  admin:
    members: [gpt-4o]
```

Busbar reports:

```text
BUSBAR-3103: pool name 'admin' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3103
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
