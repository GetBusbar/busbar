---
title: "BUSBAR-4039: Credential sign-in refused: no signing key to key the login limiter"
description: "What Busbar error BUSBAR-4039 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4039
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The per-account limiter keys accounts with an HMAC derived from `auth.signing_key`, so every node computes the same key over the shared store. No signing key is configured, so busbar refuses each credential sign-in with 503 and does not call the plugin; it never falls back to a per-node random key, which would split the budget silently. Such a deployment cannot issue keys either. Warned once, then at debug.

## How to fix it

Configure `auth.signing_key` (`busbar --generate-signing-key`).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
