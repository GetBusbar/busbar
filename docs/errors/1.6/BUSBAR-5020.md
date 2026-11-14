---
title: "BUSBAR-5020: Decision gate restrict left no eligible lane; on_empty: weighted escape"
description: "What Busbar error BUSBAR-5020 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5020
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A decision gate's restrict left no eligible lane, and its `on_empty` policy is `weighted`, so busbar skips that restriction and falls back to weighted selection across the full pool. Normal advisory-restrict behavior.

## How to fix it

None — self-heals per request. If the restriction should be enforced strictly, set its `on_empty` to reject.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
