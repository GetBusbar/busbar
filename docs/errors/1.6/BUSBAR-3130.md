---
title: "BUSBAR-3130: The admin listener is network-exposed without mTLS"
description: "What Busbar error BUSBAR-3130 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3130
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3130: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3130
```

## What it means

`admin_listen` binds a non-loopback address but `admin_tls.client_ca` is unset, so the admin plane would accept connections from the network without client certificates.

## How to fix it

Set `admin_tls.client_ca` to require client certificates, or bind `admin_listen` to a loopback address.

## Example

```text
admin_listen: 0.0.0.0:9090
```

Busbar reports:

```text
BUSBAR-3130: admin_listen '0.0.0.0:9090' is network-exposed but the admin plane has no mTLS (admin_tls.client_ca is unset). Require client certificates by supplying admin_tls.client_ca, bind admin_listen to loopback, or set admin_require_mtls: false to deliberately run a token-only admin plane (e.g. behind a mesh). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3130
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
