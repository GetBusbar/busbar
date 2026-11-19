---
title: "BUSBAR-3140: No trust anchor applies to a TLS destination"
description: "What Busbar error BUSBAR-3140 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3140
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

`outbound.tls.roots: system` found no usable certificate in the operating system's CA bundle (refused at boot), or `outbound.tls.roots: none` is set and a TLS dial matched neither a global trust anchor nor a destination entry listing one (the dial is refused; a pinned destination is refused the same way, never a panic). busbar never opens a TLS connection it cannot verify.

## How to fix it

Install the distribution's ca-certificates package or set SSL_CERT_FILE for `roots: system`; with `roots: none`, list the CA under `outbound.tls.trust_anchors` or a matching `outbound.tls.destinations` entry; or use `roots: bundled` (the default).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
