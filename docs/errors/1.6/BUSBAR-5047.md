---
title: "BUSBAR-5047: An outbound TLS connection failed verification"
description: "What Busbar error BUSBAR-5047 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5047
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The far end's certificate did not verify: unknown issuer, wrong host name, expired, or a key that is not the pinned one. The line and the `egress.tls_verification_failed` audit record carry the dialled host, the `outbound.tls.destinations` entries that matched, the fingerprints of the operator anchors in force, and the reason; never the certificate body. busbar never skips verification.

## How to fix it

List the CA that issued the server's certificate under `outbound.tls.destinations` for that host (or `trust_anchors` for a corporate root), fix the server's certificate, or update the pin.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
