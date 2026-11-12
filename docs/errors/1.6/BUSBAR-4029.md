---
title: "BUSBAR-4029: update_key request body failed to parse (client 400)"
description: "What Busbar error BUSBAR-4029 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4029
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

An update_key request body did not parse as valid JSON, so busbar returns a generic 400, logging only the body's byte length (never the raw serde error or an input fragment). Mirror of BUSBAR-4027 for the update path. This is a CLIENT-side bad request, so it is emitted at debug.

## How to fix it

None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
