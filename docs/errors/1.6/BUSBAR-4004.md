---
title: "BUSBAR-4004: auth.chain is empty (open relay)"
description: "What Busbar error BUSBAR-4004 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4004
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain was built with no verifiers and no keys-in-chain, so every data-plane request is admitted unauthenticated — an OPEN RELAY. This is acceptable only for local development. Emitted once when the chain is built.

## How to fix it

Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. An open relay in production forwards anyone's traffic on your upstream credentials.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
