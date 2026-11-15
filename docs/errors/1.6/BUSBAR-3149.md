---
title: "BUSBAR-3149: Outbound connections go through a proxy"
description: "What Busbar error BUSBAR-3149 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3149
---

**Area:** Config (3xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

HTTP(S)_PROXY / ALL_PROXY is set. busbar judges every target's name, and when the name resolves locally it judges every address it answers and refuses a private or metadata answer even behind the proxy. A name that does not resolve locally is reached through the proxy's own resolution, so the address check is delegated to the proxy for it. One line at boot (proxy endpoint redacted, NO_PROXY) and one audit record. Trust anchors are selected by the target, never by the proxy hop.

## How to fix it

Nothing, if the proxy is yours. Make sure the proxy enforces your egress policy for names it resolves.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
