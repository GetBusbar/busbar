---
title: "BUSBAR-9103: A command-line flag is missing its value"
description: "What Busbar error BUSBAR-9103 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9103
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-9103: <flag> requires a value; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9103
```

## What it means

A flag that takes a value (such as `--config <path>` or `--providers <path>`) was the last argument, so it has nothing to read. Nothing ran; the process exited with the usage status (2).

## How to fix it

Give the flag its value, for example `busbar --config /etc/busbar/config.yaml --validate`.

## Example

```text
busbar --validate --config
```

Busbar reports:

```text
BUSBAR-9103: --config requires a value; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9103
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
