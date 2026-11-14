---
title: "BUSBAR-4001: Token-exchange could not mint a self-serve key"
description: "What Busbar error BUSBAR-4001 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4001
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An authenticated, authorized token-exchange request could not be completed because minting the self-serve key failed inside busbar (a keystore write or HMAC/signing fault), so the caller receives a 500. The identity was valid; the failure is on busbar's side, not the client's.

## How to fix it

Investigate the keystore / signing subsystem — check disk, permissions, and the key-derivation secret. The condition is rare; capture the logged detail and file a bug if it recurs.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
