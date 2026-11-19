---
title: "BUSBAR-5051: An outbound dial was refused"
description: "What Busbar error BUSBAR-5051 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5051
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

busbar refused an outbound connection: the destination guard refused the host or an address it answered, plaintext was not admitted to it (BUSBAR-3141), or no trust anchor applies (BUSBAR-3140). The line carries the verdict, the class, the host, the owning plugin and need; it is rate-limited per host and reason, and each refusal writes one `egress.dial_refused` audit record.

## How to fix it

For a private registration target, set allow_private on that declared registration. Configured provider reach applies only to its own selected base/token origins. Use TLS and configure its CA under outbound.tls when needed; metadata and strict OPEN_WEB checks remain enforced.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
