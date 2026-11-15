---
title: "BUSBAR-4034: Credential sign-in failures passed the global alarm threshold"
description: "What Busbar error BUSBAR-4034 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4034
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

More than `auth.login_limits.global.max_failures_per_minute` credential sign-in failures happened on this node in one minute: the shape of a distributed password spray. busbar does not refuse everyone; while the alarm holds it cuts each source's failure ceiling to a quarter and its submission rate to a third, and records `auth.login_alarm`. Warned once per trip; the clear is logged at info.

## How to fix it

Investigate the spray (sources, targeted accounts in the audit log). Put a WAF rate limit in front of `POST /auth/token` if it persists.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
