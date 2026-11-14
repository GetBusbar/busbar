---
title: "BUSBAR-7087: Egress credential has invalid header bytes (auth header omitted)"
description: "What Busbar error BUSBAR-7087 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7087
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An egress authorization credential contains bytes that are not valid in an HTTP header (e.g. an ASCII control character), so the Authorization header is omitted entirely rather than sent malformed — the upstream will reject the request with 401. The key itself is never logged, only the protocol name. It is raised on each request that would have carried the header.

## How to fix it

Fix the misconfigured lane's credential — the configured secret contains invalid header bytes. The protocol name in the log line locates the lane.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
