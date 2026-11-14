---
title: "BUSBAR-3005: Config overlay corrupt at boot (starting on base config.yaml alone)"
description: "What Busbar error BUSBAR-3005 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3005
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

At boot the config overlay is present but unreadable/corrupt, so busbar fails soft and starts on the base config.yaml ALONE — API-applied hooks (INCLUDING security GATES that enforce admission control), groups, and plugin version pins are NOT restored. Any gate registered only via the admin API is now ABSENT until re-applied. busbar never bricks boot on a corrupt overlay, but it must not disarm those gates silently.

## How to fix it

Fix or remove the corrupt overlay file to restore durability, then restart so the API-applied hooks and gates are re-loaded. Until then, re-apply any admin-API gates the deployment depends on, or run on base config.yaml deliberately.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
