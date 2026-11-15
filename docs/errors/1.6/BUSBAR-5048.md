---
title: "BUSBAR-5048: An expired trust anchor was withdrawn"
description: "What Busbar error BUSBAR-5048 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5048
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The hourly trust-store sweep found an operator trust anchor past its notAfter and withdrew it from new connections (audited as `egress.tls_anchor_withdrawn`). A dial whose matching destination entry has no anchor left is refused. Connections already open are unaffected.

## How to fix it

Rotate the CA, list the new one, and restart.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
