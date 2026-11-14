---
title: "BUSBAR-4024: Request-signing HMAC-SHA256 init failed — RETIRED"
description: "What Busbar error BUSBAR-4024 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4024
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Initializing HMAC-SHA256 for per-request egress signing failed, which was documented as unreachable (HMAC-SHA256 accepts a key of any length). Request signing is no longer the host's, and nothing raises this code.

## How to fix it

Nothing emits this code.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
