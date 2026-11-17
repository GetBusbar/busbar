---
title: "BUSBAR-3410: A registration's allow_private was replaced by exact advanced.allow_destinations entries"
description: "What Busbar error BUSBAR-3410 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3410
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code. A registration's `allow_private` is kept: it is core's own boolean at the declared registration and grants private reach to that registration's selected route alone. `advanced.allow_destinations` was removed, and the migration writes no entries to it.

## How to fix it

Nothing to do. Keep `allow_private: true` only on a registration that must reach a private target; cloud metadata stays refused whatever is written.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
