---
title: "BUSBAR-3141: Plaintext is not admitted to this destination"
description: "What Busbar error BUSBAR-3141 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3141
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin's connection to a destination wrote application bytes in cleartext, and the destination is neither loopback nor an exact `outbound.tls.destinations` entry with `plaintext: true`. busbar refuses the write and closes the connection: a connection that must be secured carries only a short negotiation request (at most 64 bytes) before it is. The refusal names the destination class, never the bytes.

## How to fix it

Secure the connection (turn on the plugin's TLS setting and make the server's certificate verifiable), or, if the destination must stay cleartext, add it as an exact host or IP under `outbound.tls.destinations` with `plaintext: true`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
