---
title: "BUSBAR-4036: Client address unknown: per-source login limits skipped"
description: "What Busbar error BUSBAR-4036 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4036
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar could not tell who sent a request: the server has no socket peer (an embedded server), a trusted proxy forwarded an unparseable hop, or a private or loopback peer sent `X-Forwarded-For` or `Forwarded` while `client_address.trusted_proxies` is empty, which means an ingress sits in front of busbar and every user would otherwise share one bucket. Per-source limits are skipped for such requests; the per-account limiter still applies. Warned once, then at debug.

## How to fix it

List the ingress or load balancer addresses in `client_address.trusted_proxies` (and set `client_address.header` if it sends `Forwarded`).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
