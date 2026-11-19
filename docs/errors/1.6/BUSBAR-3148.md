---
title: "BUSBAR-3148: An outbound.tls destination entry is invalid"
description: "What Busbar error BUSBAR-3148 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3148
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

An `outbound.tls.destinations` entry was refused at boot: its `match` is not a host, `*.domain`, IP or CIDR; a `pin_spki_sha256` is not `sha256/<base64>` of 32 bytes; its `client_identity` certificate or key cannot be read or do not belong together; or a `plaintext: true` entry also lists TLS settings. The line names the index and the key, never key material.

## How to fix it

Correct the entry. Client identity keys are read by core from a file or environment variable and are never handed to a plugin.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
