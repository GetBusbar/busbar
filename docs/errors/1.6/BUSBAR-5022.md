---
title: "BUSBAR-5022: Routing policy rejected the request"
description: "What Busbar error BUSBAR-5022 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5022
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A routing-policy hook rejected the request; busbar returns the policy's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

## How to fix it

None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
