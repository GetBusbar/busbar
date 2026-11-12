---
title: "BUSBAR-3116: A plane is configured while the data-plane auth chain is empty"
description: "What Busbar error BUSBAR-3116 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3116
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3116: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3116
```

## What it means

A plane section (tools, agents and the like) is configured but `auth.chain` is empty, so the plane would serve anonymous callers with wildcard grants over every registered subject, and outbound credentials would have no inbound grant to bind to.

## How to fix it

Close the data-plane chain (`auth: { chain: [keys] }` or an IdP auth plugin), or remove the plane block if this deployment does not serve it.

## Example

```text
tools:
  search: { url: https://mcp.example.com }
# no auth.chain
```

Busbar reports:

```text
BUSBAR-3116: `tools:` is configured but auth.chain is empty, which serves the MCP endpoint to ANONYMOUS callers — and a request that carries no key is never narrowed by one, so it runs with WILDCARD grants over every registered subject on that plane. It also leaves `upstream::authorise` with no inbound grant to bind busbar's outbound credentials to. Close the data-plane chain (`auth: { chain: [keys] }`, or an IdP auth plugin), or remove the `tools:` block if this deployment is not a MCP endpoint. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3116
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
