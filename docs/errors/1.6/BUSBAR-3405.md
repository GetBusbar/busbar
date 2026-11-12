---
title: "BUSBAR-3405: Migration carried refresh_ttl over to verify_ttl, whose meaning differs"
description: "What Busbar error BUSBAR-3405 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3405
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-3405: <entry>.refresh_ttl -> verify_ttl (value `<value>` carried over). The meaning CHANGED: `refresh_ttl` was a background sweep cadence (default 6h); `verify_ttl` is the MAX staleness before a `tools/call` re-verifies the upstream live (default 5s). Your value is now a drift-serving window on the request path — reconsider it: a few seconds is the new default, `0` is strict-live, and a large value is an explicit security downgrade. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3405
```

## What it means

1.5's `refresh_ttl` was a background sweep cadence (default 6h). Its replacement `verify_ttl` is the longest a cached tool listing may be served before a `tools/call` re-verifies the upstream live (default 5s). The migration carried your value over unchanged, which can leave a long drift-serving window on the request path.

## How to fix it

Review the migrated `verify_ttl`: a few seconds is the default, `0` is strict-live, and a large value is an explicit security downgrade.

## Example

```text
mcp_servers:
  search:
    refresh_ttl: 6h
```

Busbar reports:

```text
BUSBAR-3405: mcp_servers.search.refresh_ttl -> verify_ttl (value `6h` carried over). The meaning CHANGED: `refresh_ttl` was a background sweep cadence (default 6h); `verify_ttl` is the MAX staleness before a `tools/call` re-verifies the upstream live (default 5s). Your value is now a drift-serving window on the request path — reconsider it: a few seconds is the new default, `0` is strict-live, and a large value is an explicit security downgrade. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3405
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
