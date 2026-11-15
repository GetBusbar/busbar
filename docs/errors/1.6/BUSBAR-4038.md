---
title: "BUSBAR-4038: Admin door: a source's refused-credential budget is spent"
description: "What Busbar error BUSBAR-4038 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4038
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A source presented `auth.login_limits.admin.max_failures` admin credentials that were refused inside the window. Further admin requests from it get 429 `rate_limited` (BUSBAR-8108) with the real Retry-After, before any credential is judged. Requests that present no credential are never counted. Logged at warn and audited (`admin.auth_throttled`) once per source and window.

## How to fix it

Check who is guessing the admin credential from that source. Use a long random operator token (see BUSBAR-4042).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
