---
title: "BUSBAR-8017: Durable keys are inert (keys exist but `keys` is not in the running auth chain)"
description: "What Busbar error BUSBAR-8017 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8017
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A durable governance store holds virtual keys, but the running auth chain does not include the `keys` verifier, so those keys enforce nothing — every request bypasses key-based governance. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr, the same pattern as the open-relay banner, so the inert state cannot be masked by log configuration.

## How to fix it

Add `keys` to `auth.chain` so the durable keys actually gate traffic, or remove the keys if key-based governance is not intended. Until then, minted keys are dead weight.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
