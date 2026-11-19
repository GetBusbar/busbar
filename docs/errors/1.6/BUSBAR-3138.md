---
title: "BUSBAR-3138: An outbound.tls trust anchor was accepted"
description: "What Busbar error BUSBAR-3138 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3138
---

**Area:** Config (3xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

Logged once at boot for each operator trust anchor busbar accepted (SHA-256 of the DER certificate, subject, issuer, notAfter, and the scope: `global` or the destination entry), and once for the base set (`roots`: its count and a SHA-256 over the sorted set, and the bundle path for `system`). Each accepted anchor also writes one `config.tls_trust_anchor` audit record.

## How to fix it

Nothing to do. Compare the fingerprints with the CAs you intended to trust.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
