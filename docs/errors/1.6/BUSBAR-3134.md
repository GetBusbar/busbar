---
title: "BUSBAR-3134: An allowlist entry names a cloud-metadata destination"
description: "What Busbar error BUSBAR-3134 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3134
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. The global advanced.allow_destinations setting was removed. Private reach is owned by a declared registration or core-selected provider route. No route grant admits cloud metadata.

## How to fix it

Remove advanced.allow_destinations. Set allow_private only on the declared registration that requires private reach; metadata stays refused.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
