---
title: "BUSBAR-3401: --migrate-config was given no file to migrate"
description: "What Busbar error BUSBAR-3401 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3401
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3401: --migrate-config requires a path: busbar --migrate-config <old-config.yaml>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3401
```

## What it means

`busbar --migrate-config` converts one old config file and needs its path. None was given, so nothing was read or printed; the process exited with the usage status (2).

## How to fix it

Name the file: `busbar --migrate-config old-config.yaml > config.yaml`.

## Example

```text
busbar --migrate-config
```

Busbar reports:

```text
BUSBAR-3401: --migrate-config requires a path: busbar --migrate-config <old-config.yaml>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3401
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
