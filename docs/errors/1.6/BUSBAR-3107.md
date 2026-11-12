---
title: "BUSBAR-3107: A pool's on_exhausted block is invalid"
description: "What Busbar error BUSBAR-3107 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3107
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3107: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3107
```

## What it means

`on_exhausted` names a fallback pool that does not exist or the pool itself, or its `queue.max_ms` is 0 or longer than the pool's whole failover budget. Such a setting never engages: the pool 503s exactly as if it had no fallback.

## How to fix it

Point `on_exhausted.fallback_pool` at a different, defined pool, and keep `queue.max_ms` above 0 and at or below the failover budget (or raise `failover.timeout_secs`).

## Example

```text
pools:
  primary:
    members: [gpt-4o]
    on_exhausted: { fallback_pool: backup }   # no such pool
```

Busbar reports:

```text
BUSBAR-3107: pool 'primary' on_exhausted references unknown fallback pool 'backup'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3107
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
