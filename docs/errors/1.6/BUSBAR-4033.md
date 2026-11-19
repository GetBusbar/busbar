---
title: "BUSBAR-4033: Credential sign-in throttled: the client's source spent its budget"
description: "What Busbar error BUSBAR-4033 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4033
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

One client source (an IPv4 address, or an IPv6 /64 with /48 and /32 aggregates) exceeded the per-source failure ceiling or the submission rate inside the window, typically one client spraying many usernames. busbar answered 429 with Retry-After without calling the login plugin. The first refusal per source and window is logged at warn and audited; later ones log at debug.

## How to fix it

None for a single client. If every user arrives from one address (an ingress or load balancer), configure `client_address.trusted_proxies` so busbar sees the real client address.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
