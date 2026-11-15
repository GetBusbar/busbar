---
title: "BUSBAR-3028: A 1.5.5 overlay input was not read — RETIRED"
description: "What Busbar error BUSBAR-3028 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3028
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: serving no longer looks for 1.5.5 overlay inputs. The first boot of a 1.5.5 config handles them once, in the upgrade, and reports what it did. The number is kept so a log line from a pre-release build still resolves to this page.

## How to fix it

Nothing emits this code. See docs/migration-1.6.md.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
