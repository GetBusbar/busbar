---
title: "BUSBAR-4045: Credential sign-in throttled: the account's failure ceiling is reached"
description: "What Busbar error BUSBAR-4045 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4045
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A hosted credential sign-in (`POST /auth/token` with a login cookie) named an account that already has `max_failures` failed attempts inside its failure window, counted fleet-wide in the core store and keyed on an HMAC of the normalised account name (never the name). busbar answered 429 "Too many sign-in attempts" with Retry-After and did NOT call the login plugin, so the directory saw no bind. The first refusal per account and window is logged at warn and audited (`auth.login_throttled`); later ones log at debug.

## How to fix it

None for a single burst: it expires on its own. Repeated refusals for one account are a targeted attack or a user who forgot a password: see BUSBAR-4041. Keep `browser_login.max_failures` x ceil(directory reset window / failure window) below the directory's lockout threshold.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
