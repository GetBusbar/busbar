---
title: "BUSBAR-4026: admin_auth chain is EMPTY (open, anonymous, full-authority dev posture)"
description: "What Busbar error BUSBAR-4026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4026
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An EMPTY admin_auth chain was seen: the admin API's open dev posture admits every admin request anonymously with FULL authority. The live `PUT /api/v1/admin/admin-auth` applies an empty chain as 1.5.5 did, with this warning, and the open posture is then live until the chain is set again.

## How to fix it

Leave `admin_auth` empty ONLY for local development. To opt into the open posture, set `admin_auth: []` in config.yaml and restart. Otherwise configure a non-empty chain (an admin credential entry, or an admin module) before exposing the admin API to any untrusted network.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
