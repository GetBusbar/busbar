---
title: "BUSBAR-3133: A login attempt limit setting is invalid"
description: "What Busbar error BUSBAR-3133 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3133
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

A key of `auth.login_limits`, a provider's `browser_login.max_failures` or `browser_login.failure_window`, `client_address.trusted_proxies` or `client_address.header` is out of range or does not parse, so busbar refuses the config rather than run with a limit nobody chose. Counts are 1..=100 (per account) or at least 1, windows 1m..=24h, `per_account.max_failures` may not exceed `per_source.max_failures`, every trusted proxy is an IP or a CIDR, and the forwarded header is `x-forwarded-for` or `forwarded`.

## How to fix it

Fix the key the message names.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
