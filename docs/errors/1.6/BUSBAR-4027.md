---
title: "BUSBAR-4027: create_key request body failed to parse (client 400)"
description: "What Busbar error BUSBAR-4027 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4027
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A create_key request body did not parse as valid JSON, so busbar returns a generic 400. The body carries secrets (an AWS secret_access_key, the bearer being minted), so only its byte length is logged, never the raw error or an input fragment. This is a CLIENT-side bad request, not an operator problem, so it is emitted at debug.

## How to fix it

None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing, but it is not a busbar fault.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
