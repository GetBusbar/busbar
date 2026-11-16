---
title: "BUSBAR-3025: A provider URL names a private or loopback host the destination guard refuses"
description: "What Busbar error BUSBAR-3025 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3025
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A provider's `base_url` or `token_url` names a private or loopback address (an RFC 1918, loopback, link-local, CGNAT or unique-local literal, or the `localhost` name), and `advanced.block_private_addresses` is on (the default) and `advanced.allow_destinations` does not name it. The destination guard refuses every request to it, so the provider would fail on its first request rather than at startup. 1.5.5 had no such guard. Emitted once per URL at config load, naming the provider, the key and the host.

## How to fix it

Add exactly that host to `advanced.allow_destinations`, or point the provider at a public address. Turning `block_private_addresses` off also admits it, and every other private address with it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
