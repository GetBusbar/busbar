---
title: "BUSBAR-3012: auth.chain names `keys` with an empty admin_auth (refused: no admin credential can mint a key)"
description: "What Busbar error BUSBAR-3012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3012
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain names the built-in `keys` verifier while `auth.admin_auth` is explicitly empty. 1.6.0 has no open admin posture, so the config is refused: an empty admin chain identifies no one, and no admin credential could mint a key.

## How to fix it

Delete the auth.admin_auth line to use the default chain [<operator>, keys] and set the operator token (identity-providers.<operator>.token), or list the admin providers you use.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
