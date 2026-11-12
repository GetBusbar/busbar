---
title: "BUSBAR-3112: A hook definition is invalid"
description: "What Busbar error BUSBAR-3112 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3112
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3112: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3112
```

## What it means

An entry under top-level `hooks:` (or `global_hooks:`) cannot work as written: it names no plugin, a tap asks to rewrite or to be the default ordering, it takes a reserved name, more than one hook is the default, its timeout is out of range, or its `on_error` chain names an unknown fallback, a tap, an absent ranking strategy or loops.

## How to fix it

Fix the hook the message names: set `module:` to a `kind: hook` plugin, use `kind: gate` where it must decide, rename it off reserved words, and end every `on_error` chain on nothing, weighted, reject, first or a ranking strategy.

## Example

```text
hooks:
  audit-tap:
    module: audit
    kind: tap
    prompt: rw
```

Busbar reports:

```text
BUSBAR-3112: hook 'audit-tap' is a tap with `prompt: rw`, but only a gate can rewrite (a tap never replies). Use `kind: gate`, or lower to `prompt: ro`. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3112
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
