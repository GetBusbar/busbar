---
title: "BUSBAR-9012: Legacy audit table could not be migrated into the durable journal seam at boot"
description: "What Busbar error BUSBAR-9012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9012
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar found audit history in the legacy durable table but could not copy it into the neutral `plane_records` the durable audit seam now reads at boot — a store read/write hiccup, not a chain-verification failure. The migration is IDEMPOTENT and is retried on the next boot, so the pre-existing history reappears once the store is healthy; until then the seam-backed audit read (`GET /audit`) reflects only records written since this boot.

## How to fix it

Investigate the governance store's write path at boot (the same store the audit log persists to). Once it accepts writes, restart so the one-time migration completes and the durable history is restored into the seam; a transient hiccup needs no action beyond confirming the store is healthy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
