---
title: "BUSBAR-5049: A trust anchor file changed; restart to apply"
description: "What Busbar error BUSBAR-5049 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5049
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The hourly trust-store sweep found that a trust anchor file's contents differ from what busbar loaded at boot (for example cert-manager trust-manager rotated the bundle). The trust store is boot-time, so the change is not applied until restart. Logged once per change and audited as `egress.tls_anchor_file_changed`.

## How to fix it

Restart busbar to apply the new anchors (validate first).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
