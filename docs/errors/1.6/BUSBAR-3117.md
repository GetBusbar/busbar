---
title: "BUSBAR-3117: A global limit or timing setting is out of range"
description: "What Busbar error BUSBAR-3117 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3117
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3117: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3117
```

## What it means

A value under `limits:`, `health:`, `routing:` or `advanced:` is outside what busbar can run with: a timeout or interval of 0 (which fails or disables the thing it bounds), a size below its floor or above its ceiling, a duration above the 30-year ceiling the runtime's clock arithmetic can hold, or reasoning-effort budgets that are zero or not ascending. One case is converted, not refused: `advanced.usage_flush_interval_ms: 0` is raised to 1 ms and logged as a warning carrying this code.

## How to fix it

Set the named key within the range the message states, or omit it to take the default; docs/configuration.md lists every default.

## Example

```text
limits:
  upstream_request_timeout_secs: 0
```

Busbar reports:

```text
BUSBAR-3117: limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call instantly). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3117
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
