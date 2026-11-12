---
title: "BUSBAR-5029: Usage tap: read_response failed to decode a same-protocol 2xx body"
description: "What Busbar error BUSBAR-5029 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5029
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

The usage tap's `read_response` could not decode a same-protocol 2xx body into the IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

## How to fix it

None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the upstream's response shape may have changed; check for a busbar update covering it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
