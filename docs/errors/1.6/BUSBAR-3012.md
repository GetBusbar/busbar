---
title: "BUSBAR-3012: auth.chain names `keys` with an empty admin_auth (anyone can mint virtual keys)"
description: "What Busbar error BUSBAR-3012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3012
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain names the built-in `keys` verifier while `auth.admin_auth` is explicitly empty, so the admin API has no credential gating it — ANYONE can mint virtual keys through it. Acceptable only for local development.

## How to fix it

Configure `auth.admin_auth` (an admin credential entry, or an admin module granting `mint`/`full`) before exposing busbar's admin API to any untrusted network, so key minting is gated by an operator credential.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
