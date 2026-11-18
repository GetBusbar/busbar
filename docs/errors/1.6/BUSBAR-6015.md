---
title: "BUSBAR-6015: A plugin requested the retired UPGRADE_VERIFY_OFF flag (refused)"
description: "What Busbar error BUSBAR-6015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6015
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin requested `UPGRADE_VERIFY_OFF` on a connection upgrade. Busbar refuses this flag in 1.6.0: a plugin cannot turn off certificate verification through the upgrade call. The refusal is logged once per instance and audited.

## How to fix it

Upgrade the plugin to a version that uses the core-held transport policy on its declared need. Configure verified TLS; for a server with a private CA, configure `advanced.tls.trust_anchors` and `advanced.tls.destinations`. Any deliberate exception uses the instance's explicit `insecure_transport` policy, never `UPGRADE_VERIFY_OFF`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
