---
title: "BUSBAR-3115: The auth chain cannot authenticate as configured"
description: "What Busbar error BUSBAR-3115 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3115
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3115: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3115
```

## What it means

The data-plane or admin auth chain is incomplete: it names a module that was removed, it verifies busbar-signed keys without an `auth.signing_key` or without any way to mint one, an operator token sits on a module that is not the operator provider, or the operator token has no answer. Busbar refuses rather than start with an auth surface that admits the wrong callers or none.

## How to fix it

Follow the message: generate a signing key with `busbar --generate-signing-key` and reference it from `auth.signing_key`, name `keys` or an IdP plugin in `auth.chain`, and keep the operator token on the operator provider.

## Example

```text
auth:
  chain: [keys]          # no signing_key
```

Busbar reports:

```text
BUSBAR-3115: auth.signing_key is required for signed-token auth (auth.chain names the built-in `keys` verifier), but none is set - and busbar no longer auto-generates one. Generate a key with `busbar --generate-signing-key`, then set auth.signing_key to a secret reference for it (a shorthand an admitted secret module declares, or `{ module: …, settings: … }`; a SHARED secret across nodes for a fleet). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3115
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
