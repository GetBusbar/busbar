---
title: "BUSBAR-3139: An outbound.tls trust anchor expires within 30 days"
description: "What Busbar error BUSBAR-3139 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3139
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An operator trust anchor's notAfter is within 30 days. The warning is logged at boot and repeated once a day by the hourly trust-store sweep. When the anchor expires, the sweep withdraws it from new connections (BUSBAR-5048) and the next boot refuses it (BUSBAR-3137).

## How to fix it

Rotate the CA: list the new CA beside the old one, restart, then remove the old one once every server presents a chain to the new CA.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
