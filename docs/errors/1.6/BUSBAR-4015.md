---
title: "BUSBAR-4015: OAuth token endpoint returned a 200 with an empty access_token"
description: "What Busbar error BUSBAR-4015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4015
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The upstream OAuth token endpoint answered 200 but with an EMPTY access_token. busbar treats it as a (retryable) mint failure rather than storing it, because an empty token collides with the pre-first-mint sentinel and would wedge the lane permanently. It retries on the refresh cadence.

## How to fix it

Investigate the OAuth token endpoint / client-credentials configuration — a 200 with no token usually means a misconfigured client, scope, or audience. Egress to that upstream 401s until a non-empty token is minted.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
