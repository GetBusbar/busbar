---
title: "BUSBAR-3144: A plaintext destination entry is not an exact host or IP"
description: "What Busbar error BUSBAR-3144 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3144
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

`plaintext: true` on an `outbound.tls.destinations` entry is accepted only on an exact host name or an exact IP. A wildcard or a CIDR would admit cleartext to destinations nobody named.

## How to fix it

Write one entry per host or IP that must be reached in clear.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
