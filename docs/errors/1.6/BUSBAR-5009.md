---
title: "BUSBAR-5009: on_error fallback hook deadline exceeded; continuing down the chain"
description: "What Busbar error BUSBAR-5009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5009
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An `on_error` fallback hook exceeded its deadline, so busbar continued down the fallback chain. Warned once per fault window; continued timeouts log at debug.

## How to fix it

Investigate why the fallback hook is slow, or raise its timeout if the latency is expected. The chain still resolves via a later link or the terminal policy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
