---
title: "BUSBAR-5023: Routing policy restrict left no eligible lane; on_empty: weighted escape"
description: "What Busbar error BUSBAR-5023 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5023
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, so busbar escapes to full-pool weighted selection. Normal advisory-restrict behavior.

## How to fix it

None — self-heals per request. Set `on_empty` to reject if the restriction must be enforced strictly.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
