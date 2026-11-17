---
title: "BUSBAR-3160: A plugin instance would connect without TLS"
description: "What Busbar error BUSBAR-3160 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3160
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

At `check`, a plugin instance declared an endpoint busbar would dial without TLS (a TCP, `http://` or unix-socket destination with no TLS) and the instance has no `insecure_transport` acceptance for it. busbar 1.6.0 connects only over verified TLS and nothing is exempt, not loopback and not unix sockets. The configuration is refused before any connection is opened.

## How to fix it

Turn on TLS for the connection and make the server's certificate verifiable (a CA under `advanced.tls.trust_anchors`, or a pin under `advanced.tls.destinations`); or, if verified TLS is not possible, add `insecure_transport: { accept: plaintext, reason: "<why this is acceptable>" }` to the instance's block.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
