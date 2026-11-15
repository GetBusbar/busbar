---
title: "BUSBAR-4032: Sender-constrained (DPoP) credential refused"
description: "What Busbar error BUSBAR-4032 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4032
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A DPoP-bound token or DPoP presentation was refused because its sender constraint was not met or cannot be verified here

## How to fix it

Have the client present a DPoP proof (with `oauth_as` configured) or an unbound token; if the IdP binds tokens for bearer-only clients, change the IdP client

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
