---
title: "BUSBAR-4011: auth.chain names `keys` alongside upstream_credentials: passthrough"
description: "What Busbar error BUSBAR-4011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4011
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain names the `keys` verifier while `upstream_credentials` is set to `passthrough`. keys-in-chain requires a valid virtual key on every request and supersedes passthrough's accept-and-forward-the-caller-credential intent, so passthrough never takes effect. Warned once at first request.

## How to fix it

Resolve the config conflict: use `upstream_credentials: own` (or omit it) alongside `keys`, or drop `keys` from the chain if you genuinely want to forward caller credentials. The two settings are mutually exclusive.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
