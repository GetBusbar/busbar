---
title: "BUSBAR-3111: A pool's hook list is invalid"
description: "What Busbar error BUSBAR-3111 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3111
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3111: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3111
```

## What it means

A pool's `hooks:` list names a hook that is not defined under top-level `hooks:`, names a tap (only a gate can influence routing), or names a built-in ranking strategy this binary was built without.

## How to fix it

Define the hook under top-level `hooks:`, use a gate, or name a strategy this build carries (`busbar --help` lists the build's features).

## Example

```text
pools:
  default:
    members: [gpt-4o]
    hooks: [pii-scrub]   # not defined under hooks:
```

Busbar reports:

```text
BUSBAR-3111: pool 'default' references unknown hook 'pii-scrub'; define it under top-level `hooks:`. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3111
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
