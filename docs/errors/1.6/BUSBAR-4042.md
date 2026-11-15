---
title: "BUSBAR-4042: Operator token is shorter than 32 bytes"
description: "What Busbar error BUSBAR-4042 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4042
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin operator token is operator-chosen and compared by digest, so its entropy is the only thing between an online guesser and the admin API. A token shorter than 32 bytes is warned at every boot and reload in 1.6 and will be refused in 1.7.

## How to fix it

Replace it with at least 32 random bytes (for example `openssl rand -hex 32`).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
