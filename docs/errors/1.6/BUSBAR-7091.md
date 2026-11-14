---
title: "BUSBAR-7091: Spent-approval ledger unreachable — redemption refused — RETIRED"
description: "What Busbar error BUSBAR-7091 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7091
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The shared spent-approval ledger could not be reached, so an approval redemption was REFUSED: a ledger that cannot say whether an approval was already spent must not be read as saying it was not (a double-spend on a money-moving tool is the defect the gate exists to stop).

## How to fix it

Nothing emits this code. A one-time approval is redeemed through the host's records.claim service.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
