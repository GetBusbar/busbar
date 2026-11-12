---
title: "BUSBAR-5007: on_error fallback hook answered for the failed gate"
description: "What Busbar error BUSBAR-5007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5007
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

After a routing gate failed, one of its configured `on_error` fallback hooks answered and decided the request. This is a RECOVERY signal: the fallback chain did its job.

## How to fix it

None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names the primary hook to fix.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
