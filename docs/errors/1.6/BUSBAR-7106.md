---
title: "BUSBAR-7106: A plane declares a record kind the kernel keeps its own records under (the plane is refused)"
description: "What Busbar error BUSBAR-7106 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7106
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane's Statement declares a record kind that the kernel keeps its own records under (`ticket`, where a minted ticket's record is kept). A plane's declared kind names the rows its retention rule governs, so admitting it would let that plane purge the kernel's records under its own rule. busbar refuses the plane instance at its admit, so the boot (or the reload) that would open it fails, naming the instance and the kind. Nothing of the instance is registered.

## How to fix it

Use a plane build that does not declare a kernel record kind: rename the plane's record kind (it is the plugin author's word, in its Statement's record kinds) and rebuild. There is no configuration override; the kernel's kinds are never shared.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
