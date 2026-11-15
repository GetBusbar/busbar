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

A secret is referenced in a way busbar cannot resolve safely: `none` where a credential is required, a reference form the setting does not accept, a shorthand no admitted secret module declares, or module-level settings on a secret module linked into this build that takes none.

## How to fix it

Write the canonical `{ module: <secret module>, settings: {...} }` reference, or a shorthand an admitted secret module declares (`busbar --list-plugins` shows them).

## Example

```text
auth:
  signing_key: { vault-path: signing }   # no admitted secret module declares `vault-path`
```

Busbar reports:

```text
BUSBAR-3121: auth.signing_key: `{vault-path: …}` is a secret shorthand, and no admitted secret module declares `vault-path`. Install a signed `kind: secret` module that declares `vault-path` into plugins.dir and admit it (plugins.enabled, plugins.trust), or write the canonical `{ module: <secret module>, settings: { … } }` reference. `busbar --list-plugins` shows what was admitted. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3121
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
