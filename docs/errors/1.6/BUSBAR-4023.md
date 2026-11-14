---
title: "BUSBAR-4023: oauth_as expired-record sweep failed (retrying next tick)"
description: "What Busbar error BUSBAR-4023 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4023
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

The oauth_as authorization-server sweep of expired records failed for a tick — typically a transient store hiccup — so busbar retries on the next tick. Expired records simply linger until a sweep succeeds. Warned once on entry to the failing state; recurrence logs at debug so a persistent store problem cannot spam.

## How to fix it

None if it clears on the next tick. Sustained failures indicate an oauth_as store problem worth investigating; expired records accumulate until a sweep succeeds.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
