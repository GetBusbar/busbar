---
title: "BUSBAR-8012: SAFE MODE: config overlay not merged (running on base config.yaml alone)"
description: "What Busbar error BUSBAR-8012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8012
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar was booted with `--safe-mode`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay file is untouched, not deleted.

## How to fix it

This is an operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--safe-mode` to re-apply the overlay. Until then, API-registered hooks are not in effect.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
