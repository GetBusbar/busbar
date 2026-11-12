---
title: "BUSBAR-3108: A pool's affinity header name is invalid"
description: "What Busbar error BUSBAR-3108 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3108
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3108: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3108
```

## What it means

`affinity.header_name` must be a valid, non-empty, ASCII HTTP field-name of at most 64 characters; anything else would silently disable session affinity.

## How to fix it

Set `affinity.header_name` to a plain header name such as `x-session-id`, or remove the affinity block.

## Example

```text
pools:
  chat:
    members: [gpt-4o]
    affinity: { mode: header, header_name: "" }
```

Busbar reports:

```text
BUSBAR-3108: pool 'chat' affinity.header_name must not be empty (an empty HTTP header field-name silently disables session affinity). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3108
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
