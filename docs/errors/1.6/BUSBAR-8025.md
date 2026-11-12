---
title: "BUSBAR-8025: A recoverable credential written before 1.6.0 is stored in the clear"
description: "What Busbar error BUSBAR-8025 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8025
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A recoverable credential (a signed-request secret) minted by 1.5.5 is stored as v1:plain. It still authenticates. A boot or reload with credentials.at_rest.key configured re-seals it under that key.

## How to fix it

Configure credentials.at_rest.key (a secret reference resolving to 32 random bytes) and reload; the row is re-sealed and no longer stored in the clear.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
