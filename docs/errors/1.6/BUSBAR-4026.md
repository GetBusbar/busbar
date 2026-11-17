---
title: "BUSBAR-4026: admin_auth chain is EMPTY (it identifies no one; 1.6.0 has no open admin posture)"
description: "What Busbar error BUSBAR-4026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4026
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An EMPTY admin_auth chain was seen. 1.6.0 has no anonymous admin posture: an empty chain identifies no one, so it admits no admin request and earns no scope. Boot and `busbar --validate` refuse `auth.admin_auth: []`, and the live `PUT /api/v1/admin/admin-auth` refuses an empty chain.

## How to fix it

Delete the auth.admin_auth line to use the default chain [<operator>, keys], where <operator> is the name of your identity-providers entry for the first-party operator credential plugin (module: admin-tokens). Give that entry `settings: {sha256: "<digest>"}`, where <digest> is the SHA-256 of your admin token as 64 lower-case hex characters. To mint a token and its digest: `token=$(openssl rand -base64 32); printf %s "$token" | openssl dgst -sha256 -r | cut -d' ' -f1`. Keep the token as a secret and send it as `Authorization: Bearer` followed by the token. Or list the admin providers you use in auth.admin_auth.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
