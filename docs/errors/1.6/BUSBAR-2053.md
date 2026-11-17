---
title: "BUSBAR-2053: Exporter loss evidence remains unconfirmed or a producer reported after quiescence"
description: "What Busbar error BUSBAR-2053 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2053
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The observer could not yet confirm its retained first-loss evidence, or an exporter called it after shutdown observation intake closed. The original remains retained; an accepted native audit original is never replaced by a retry. Shutdown cannot report successful observation settlement while evidence or a late callback is unresolved.

## How to fix it

Restore native audit availability and allow settlement within the existing shutdown budget. A callback after producer quiescence indicates a runtime lifecycle defect. Preserve stderr and the incomplete-shutdown report.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
