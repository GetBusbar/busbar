---
title: "BUSBAR-8010: rotate_key: new generation committed, but cache reconcile failed (new secret not returned)"
description: "What Busbar error BUSBAR-8010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8010
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin key rotation committed the new generation in the store — so the PREVIOUS credential is permanently dead — and evicted the key from the caches, but the follow-up cache reconcile failed, so the freshly-minted secret could not be returned to the admin. The rotation IS durable; the new secret is simply lost from this response. Rare admin path.

## How to fix it

Re-rotate the key to obtain a fresh secret — the previous credential is already dead and will not come back. Investigate the governance store's reachability, which is why the reconcile failed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
