---
title: "BUSBAR-4040: Credential method held open after repeated provider outages"
description: "What Busbar error BUSBAR-4040 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4040
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The login plugin answered `Outage` (directory or IdP unreachable) five times within a minute. busbar answers sign-ins for that method with 503 "Couldn't reach your provider" and Retry-After: 30 for 30 seconds, without calling the plugin and without counting the attempts against anyone, so an outage does not throttle every user. Warned each time it opens.

## How to fix it

Restore the directory or identity provider the method uses.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
