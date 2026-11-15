---
title: "BUSBAR-3021: A deprecated environment variable is set and still honored — RETIRED"
description: "What Busbar error BUSBAR-3021 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3021
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.5.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Serving no longer applies deprecated operational environment overrides. Move the provider, worker and upstream HTTP settings they set into config.yaml; old file-overlay selection is read only by the one-time upgrade boot.

## How to fix it

Run the 1.6 migration before serving, review and validate its output, then remove the retired variables from launchers. See docs/migration-1.6.md. See BUSBAR-3029.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
