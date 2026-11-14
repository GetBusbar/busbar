---
title: "BUSBAR-4010: Admin request forbidden (audit record suppressed this window)"
description: "What Busbar error BUSBAR-4010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4010
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

An admin request was forbidden (insufficient scope for the path), and a durable audit record for it was suppressed because one was already written for this principal in the current rate window. This is a per-request signal of a CLIENT-side authorization failure, not an operator problem, so it is emitted at debug to avoid log spam under a client that keeps retrying a forbidden call.

## How to fix it

None — self-heals; the client is being correctly refused. Persistent volume from one principal indicates a misconfigured client or a probe; the durable audit chain already carries the first occurrence per window.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
