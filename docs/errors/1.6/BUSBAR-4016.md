---
title: "BUSBAR-4016: OAuth token mint (refresh) failed; retrying"
description: "What Busbar error BUSBAR-4016 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4016
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The background OAuth token refresh failed to mint a new token. busbar keeps serving the current token and retries soon; if retries keep failing past expiry, egress requests carry a stale/empty token and the upstream 401s. Fires on the refresh cadence, not per request.

## How to fix it

Investigate the OAuth token endpoint — a transient outage self-heals on the next retry; sustained failures mean a credential/endpoint/network problem that will 401 egress once the current token expires.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
