---
title: "BUSBAR-5052: The local egress framer failed"
description: "What Busbar error BUSBAR-5052 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5052
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The engine's local outbound framer could not render the request before any answer. The log identifies the pool, member and framing fault. The request is refused as an internal error without charging member health.

## How to fix it

Inspect the framing fault and the named pool and member in the log. Report a reproducible local framing failure with the engine version and request shape, excluding credentials and secret content.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
