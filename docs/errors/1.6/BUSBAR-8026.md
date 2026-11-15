---
title: "BUSBAR-8026: A plane member's upstream credential could not be refreshed"
description: "What Busbar error BUSBAR-8026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8026
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar renews each plane member's upstream_credential off the request path, at half its lease_ttl_ms (at most every five minutes). A renewal failed: the source could not be read (cause resolve: unavailable, internal fault, an empty or non-text value), or the value changed and the auth plugin refused the new one (cause reopen, at ERROR). The value already held is still presented until its lease ends, and the renewal is retried with a jittered backoff. Reported on the first failure, then at most once a minute per member (also after the lease has ended); members on the same source within that minute are counted in its others field. Each report is audited as upstream_credential.refresh, degraded. An A2A member whose lease ends meanwhile has its hops refused as BUSBAR-7013.

## How to fix it

Check the source the reference field names (the file, the environment variable or the secret module) and the error field. For cause reopen, the value at the source is one the auth plugin cannot present (for example a header value with illegal characters): correct it at the source. The next successful refresh logs that it refreshed again and is audited as applied.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
