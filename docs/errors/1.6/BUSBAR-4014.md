---
title: "BUSBAR-4014: Minted OAuth token contains invalid header bytes (auth header omitted)"
description: "What Busbar error BUSBAR-4014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4014
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A token minted for egress contains bytes invalid in a header value, so the `Bearer` auth header is omitted and the upstream rejects the request with 401. It is raised when such a token is minted.

## How to fix it

Investigate the token endpoint: a minted token with a control character in it is malformed. Egress to that upstream 401s until a well-formed token is minted.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
