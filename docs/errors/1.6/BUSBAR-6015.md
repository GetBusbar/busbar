---
title: "BUSBAR-6015: A plugin used a deprecated ABI value (refused from 1.7.0)"
description: "What Busbar error BUSBAR-6015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6015
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin secured an operator-infrastructure connection with `UPGRADE_VERIFY_OFF`, so the far end's certificate is not verified (postgres `sslmode=prefer`, valkey `#insecure`). The value is honoured in 1.6.x, deprecated, and refused from 1.7.0. The first use per instance is logged and audited.

## How to fix it

Configure the server with a certificate the plugin can verify (`sslmode=require` or `verify-full`, `rediss://` without `#insecure`); for a server with a private CA, list that CA under `advanced.tls.trust_anchors` (or the server under `advanced.tls.destinations`).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
