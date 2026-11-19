---
title: "BUSBAR-3137: An outbound.tls trust anchor is not a usable CA"
description: "What Busbar error BUSBAR-3137 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3137
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

A trust anchor listed under `outbound.tls.trust_anchors` or `outbound.tls.destinations[].trust_anchors` was refused at boot: it could not be read, does not parse as PEM, holds no certificate or holds a private key, is not an X.509 v3 CA (`basicConstraints CA:TRUE`, and `keyCertSign` when `keyUsage` is present), is not yet valid (more than five minutes before `notBefore`) or has expired, or rustls does not accept it. busbar refuses to boot rather than open connections with a trust set the operator did not intend. The line names the key, the index, the source (file, env or inline) and the destination it scopes; never the certificate bytes.

## How to fix it

List the CA that issued the server's certificate (not the server's own certificate), as a PEM file, environment variable or inline PEM. Rotate an expired CA before restarting. A self-signed server certificate (`CA:FALSE`) is not a trust anchor: issue the server a certificate from a CA you control and list that CA.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
