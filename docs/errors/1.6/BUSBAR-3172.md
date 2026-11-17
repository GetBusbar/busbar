---
title: "BUSBAR-3172: A listener would serve plaintext without an acceptance"
description: "What Busbar error BUSBAR-3172 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3172
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3172: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3172
```

## What it means

The data listener (`listen`) or the admin listener (`admin_listen`) has no TLS (`tls:` / `admin_tls:`) and no explicit acceptance to serve in the clear, or an acceptance is written beside TLS. Every listener without TLS needs its acceptance, loopback included, because anything sent to it, credentials included, can be read and altered on the network path. The upgrade from 1.5.x does not write the acceptance for you. A Store overlay cannot set it; an overlay that sets TLS makes a file acceptance inert, and the boot warns that it can be removed.

## How to fix it

Add `tls:` (or `admin_tls:`) with a certificate and key, or, to serve that listener in the clear deliberately, write `listen_insecure_transport: { accept: [plaintext], reason: "..." }` (or `admin_listen_insecure_transport:`) with your real reason in config.yaml. A listener that has TLS takes no acceptance.

## Example

```text
listen: 0.0.0.0:8080
```

Busbar reports:

```text
BUSBAR-3172: `listen` 0.0.0.0:8080 has no TLS and no acceptance: it would serve plaintext, so anything sent to it, credentials included, could be read and altered on the network path; add `tls:` (cert and key), or to serve it in the clear deliberately add `listen_insecure_transport: { accept: [plaintext], reason: "<why>" }` with your real reason. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3172
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
