---
title: "BUSBAR-4013: Egress API key contains invalid header bytes (auth header omitted)"
description: "What Busbar error BUSBAR-4013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4013
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A configured static egress credential contains bytes that are invalid in a header value (an ASCII control character, such as a trailing newline), so the auth plugin omits the auth header and the upstream rejects the request with 401. It is raised on each request that would have carried the header.

## How to fix it

Fix the credential's configured value: strip the control character (often a trailing newline in the secret's source). Egress to that upstream 401s until it is fixed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
