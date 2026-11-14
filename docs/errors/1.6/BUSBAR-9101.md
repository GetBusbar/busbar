---
title: "BUSBAR-9101: The command line names an argument busbar does not know"
description: "What Busbar error BUSBAR-9101 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9101
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-9101: unrecognized argument '<argument>'; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9101
```

## What it means

busbar was started with an argument that is neither a flag it accepts nor the value of one. Nothing ran; the process exited with the usage status (2).

## How to fix it

Check the spelling against `busbar --help`. Configuration is not passed on the command line: put settings in config.yaml and point busbar at it with `--config <path>`.

## Example

```text
busbar --valdiate
```

Busbar reports:

```text
BUSBAR-9101: unrecognized argument '--valdiate'; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9101
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
