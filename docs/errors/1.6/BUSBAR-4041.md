---
title: "BUSBAR-4041: An account has been throttled for more than four consecutive windows"
description: "What Busbar error BUSBAR-4041 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4041
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

Someone keeps spending one account's failure budget, window after window. busbar keeps refusing (inside busbar only; the directory is protected), but the real user cannot sign in either. The log carries the account's key fingerprint, never the name. Warned once per window while it lasts.

## How to fix it

Treat it as a security event: find the sources in the audit log and block them upstream. Tell the user; consider a trusted network path for them.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
