---
title: "BUSBAR-3119: A group's limits are invalid"
description: "What Busbar error BUSBAR-3119 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3119
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3119: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3119
```

## What it means

A group under `groups:` sets a limit of 0, which rejects every request through the group instead of bounding it.

## How to fix it

Use a positive limit, or remove the limit to leave that dimension unbounded.

## Example

```text
groups:
  eng:
    limits:
      - { requests: 0, per: minute }
```

Busbar reports:

```text
BUSBAR-3119: groups.eng has a `requests` limit of 0, which rejects every request through the group from the first admission; set a positive amount, or set `enabled: false` to freeze the group explicitly. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3119
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
