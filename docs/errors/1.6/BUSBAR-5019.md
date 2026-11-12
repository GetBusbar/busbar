---
title: "BUSBAR-5019: Decision gate rejected the request"
description: "What Busbar error BUSBAR-5019 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5019
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A decision-gate hook rejected the request; busbar returns the gate's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

## How to fix it

None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
