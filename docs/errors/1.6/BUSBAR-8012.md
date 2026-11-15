---
title: "BUSBAR-8012: IGNORE OVERLAY: config overlay not merged (running on base config alone)"
description: "What Busbar error BUSBAR-8012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8012
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar was booted with `--ignore-overlay`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml/providers.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay in the Store is untouched, not deleted. `GET /api/v1/admin/info` reports `overlay_ignored: true`.

## How to fix it

Operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--ignore-overlay`. An admin reload, apply or config write in this process re-merges the Store overlay and persists to it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
