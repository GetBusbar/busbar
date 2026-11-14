---
title: "BUSBAR-3121: A secret reference or secret module setting is invalid"
description: "What Busbar error BUSBAR-3121 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3121
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3121: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3121
```

## What it means

A secret is referenced in a way busbar cannot resolve safely: `none` where a credential is required, a reference form the setting does not accept, or module-level settings on a built-in secret module that takes none.

## How to fix it

Reference the secret as `{ env: VAR }`, `{ file: /path }` or `{ module: <secret-module>, settings: {...} }`, as the message shows for the setting it names.

## Example

```text
secrets:
  env: { prefix: BUSBAR_ }
```

Busbar reports:

```text
BUSBAR-3121: secrets.env: the built-in 'env' secret module takes no module-level settings. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3121
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
