---
title: "BUSBAR-3110: A pool's circuit-breaker settings are invalid"
description: "What Busbar error BUSBAR-3110 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3110
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3110: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3110
```

## What it means

A `breaker:` value is out of range: a cooldown of 0 (which re-admits a tripped backend at once), `max_cooldown_secs` below `base_cooldown_secs`, a trip `min_requests`, `window_secs` or `consecutive_n` of 0, or an error-rate `threshold` outside (0.0, 1.0].

## How to fix it

Fix the field the message names under `pools.<pool>.breaker:`; docs/circuit-breaker.md gives every default.

## Example

```text
pools:
  default:
    members: [gpt-4o]
    breaker: { base_cooldown_secs: 0 }
```

Busbar reports:

```text
BUSBAR-3110: pool 'default' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3110
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
