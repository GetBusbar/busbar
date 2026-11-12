---
title: "BUSBAR-3127: A plane section's failover pool is invalid"
description: "What Busbar error BUSBAR-3127 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3127
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3127: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3127
```

## What it means

A failover pool inside a plane section (`tools.pools`, `agents.pools`, ...) cannot fail over as written: it has fewer than two members or more than the breaker's lane table holds, it shares its name with a registration, it names a member twice, a member belongs to another plane or is not defined, a member sits in two pools, or a `repeatable:` entry is empty.

## How to fix it

Fix the pool the message names: list two or more distinct members defined in the same plane section, give the pool its own name, and keep each registration in at most one pool.

## Example

```text
tools:
  pools:
    search: { members: [brave] }
```

Busbar reports:

```text
BUSBAR-3127: tools.search: a failover pool needs at least TWO members (it has 1). A pool with one member has nowhere to fail over to, so it changes nothing; remove it or add the second registration. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3127
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
