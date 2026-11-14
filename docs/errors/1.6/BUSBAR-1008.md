---
title: "BUSBAR-1008: Group delete could not read keys to check bindings (admin 500)"
description: "What Busbar error BUSBAR-1008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1008
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

Deleting a group requires a full key scan to count how many keys are still bound to it, and that store read failed, so busbar answers the admin delete with a generic 500 rather than delete a group with unknown live bindings. No group state was changed.

## How to fix it

Investigate the governance store's reachability — the key scan could not complete. Retry the delete once the store is healthy; a transient read error self-heals.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
