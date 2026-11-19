---
title: "BUSBAR-3145: A destination wildcard is too wide"
description: "What Busbar error BUSBAR-3145 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3145
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

An `outbound.tls.destinations` `match` is a wildcard over a single label (for example `*.com` or `*.internal`), which would scope the entry's CAs, pins or identity to names nobody named. Public-suffix-list wildcards (for example `*.co.uk`) are not detected in 1.6.0.

## How to fix it

Name the domain you own: `*.corp.example.com`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
