---
title: "BUSBAR-5024: Routing policy restrict left no eligible lane (on_empty: reject)"
description: "What Busbar error BUSBAR-5024 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5024
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A routing policy's restrict left no eligible lane and its `on_empty` is reject (fail-closed), so busbar rejects the request rather than route to an ineligible upstream. Correct compliance behavior.

## How to fix it

None — self-heals per request. If unexpected, review pool membership tags against the restrict's required tags.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
