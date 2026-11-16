---
title: "BUSBAR-9102: A command's arguments do not fit together"
description: "What Busbar error BUSBAR-9102 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9102
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-9102: <reason>; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9102
```

## What it means

A command-line command (a principal transition) was given arguments it cannot act on: a missing companion flag, a conflicting pair, or a malformed value. The text after the code names which. Nothing ran; the process exited with the usage status (2).

## How to fix it

Fix the arguments the message names; `busbar --help` lists every command with its flags.

## Example

```text
busbar --principal-transition
```

Busbar reports:

```text
BUSBAR-9102: principal transition flags require explicit values; try 'busbar --help'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9102
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
