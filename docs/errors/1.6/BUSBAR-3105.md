---
title: "BUSBAR-3105: A pool's member list is invalid"
description: "What Busbar error BUSBAR-3105 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3105
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3105: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3105
```

## What it means

A pool has no members, a member's `weight` is 0, a member's `attempt_timeout_ms` is 0 or above the 30-year ceiling, or a member names a model that is not defined (or whose provider is not). A pool with no routable member answers every request with a misleading 503.

## How to fix it

Fix the member the message names under `pools.<pool>.members:`: name a model defined under `models:`, use a weight of at least 1 and a positive timeout, or remove the pool.

## Example

```text
pools:
  default:
    members: [gpt-4o, claude-sonet]   # typo
```

Busbar reports:

```text
BUSBAR-3105: pool 'default' references unknown model 'claude-sonet'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3105
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
