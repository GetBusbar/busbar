---
title: "BUSBAR-3027: A 1.5.5 file overlay held settings this Store had not imported — RETIRED"
description: "What Busbar error BUSBAR-3027 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3027
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: serving no longer checks for a 1.5.5 file overlay. The first boot of a 1.5.5 config folds the overlay 1.5.5 read into config.yaml, keeps both originals as `.1.5.5` backups, and a migrated config never reads it again. The number is kept so a log line from a pre-release build still resolves to this page.

## How to fix it

Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot folds its overlay. See docs/migration-1.6.md.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
