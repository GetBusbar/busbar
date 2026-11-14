---
title: "BUSBAR-3109: Pools' on_exhausted fallbacks form a cycle"
description: "What Busbar error BUSBAR-3109 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3109
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3109: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3109
```

## What it means

Following `on_exhausted.fallback_pool` from pool to pool leads back to a pool already visited. The runtime loop guard would cut the ring on re-entry, so every pool in it 503s instead of degrading.

## How to fix it

Break the cycle the message prints: point one pool at a pool outside the ring, or remove its `on_exhausted`.

## Example

```text
pools:
  a: { members: [m1], on_exhausted: { fallback_pool: b } }
  b: { members: [m2], on_exhausted: { fallback_pool: a } }
```

Busbar reports:

```text
BUSBAR-3109: fallback_pool cycle detected: a -> b -> a; on_exhausted fallback chains must not loop — the runtime loop guard terminates a cycle on re-entry, so every pool in the ring 503s instead of degrading. Break the cycle (point one pool at a non-looping pool or remove its on_exhausted). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3109
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
