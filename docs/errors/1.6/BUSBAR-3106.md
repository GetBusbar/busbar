---
title: "BUSBAR-3106: A pool's failover block is invalid"
description: "What Busbar error BUSBAR-3106 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3106
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3106: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3106
```

## What it means

`failover.timeout_secs` is 0 (every request would 503 before its first attempt) or above 24 hours, or `failover.exclusions` names something that is not a member of the pool (so it benches nothing).

## How to fix it

Set `failover.timeout_secs` between 1 and 86400 and list only the pool's own members under `failover.exclusions`.

## Example

```text
pools:
  default:
    members: [gpt-4o]
    failover: { timeout_secs: 0 }
```

Busbar reports:

```text
BUSBAR-3106: pool 'default' failover.timeout_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3106
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
