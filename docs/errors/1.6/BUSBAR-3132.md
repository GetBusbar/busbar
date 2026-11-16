---
title: "BUSBAR-3132: An outbound destination is refused by the egress policy"
description: "What Busbar error BUSBAR-3132 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3132
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3132: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3132
```

## What it means

A configured outbound URL (an upstream, a token endpoint, a sink) is not one busbar will send to: it is malformed, uses plaintext for a public host, or targets a blocked cloud-metadata host.

## How to fix it

Use an `https://` URL for a public host, fix the URL the message names, or point the URL at its real host: no setting admits a cloud-metadata host (BUSBAR-3136).

## Example

```text
providers:
  remote: { base_url: http://api.example.com }
```

Busbar reports:

```text
BUSBAR-3132: provider 'remote' base_url must use a secure connection for a public host; plaintext is permitted only for a private/loopback local-model upstream. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3132
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
