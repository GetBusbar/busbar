---
title: "BUSBAR-6017: A plugin declares a retired ABI value"
description: "What Busbar error BUSBAR-6017 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6017
---

**Area:** Plugins (6xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

A plugin's Statement or need uses something the 1.6.0 ABI retired: the plane trust role `TRUST_PRIVATE_REACH` (4), or an operator-infrastructure need over a framed transport (`http`, `grpc`) that names no config-declared target (`target_from`). The operator-infrastructure class is a property of a target the operator configured, never a plugin's choice. The plugin (for a trust role) or the need is refused, naming what it declared. A carrier need (`tcp`, `unix`) without a declared target is deprecated and refused from 1.7.0.

## How to fix it

Upgrade the plugin to a release built against busbar 1.6.0. A plugin author drops the retired role, and declares `target_from` on an operator-infrastructure need.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
