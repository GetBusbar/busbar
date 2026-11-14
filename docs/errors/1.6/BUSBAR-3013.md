---
title: "BUSBAR-3013: passthrough provider has a non-empty api_key that is never forwarded (inert config)"
description: "What Busbar error BUSBAR-3013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3013
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A provider is configured with a NON-EMPTY api_key while `upstream_credentials` is `passthrough`, under which the upstream key is the caller's own token (or empty), so the configured api_key is NEVER forwarded — it is inert dead config. A legitimate passthrough provider may itself sign each request and need no static key, hence a warning rather than a hard reject.

## How to fix it

If you intended static-key gating, use `upstream_credentials: own` (plus an auth chain). Otherwise clear the referenced provider secret so the config reflects that no static key is used on that passthrough provider.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
