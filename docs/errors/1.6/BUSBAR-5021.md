---
title: "BUSBAR-5021: Decision gate restrict left no eligible lane (on_empty: reject)"
description: "What Busbar error BUSBAR-5021 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5021
---

**Area:** Proxy & routing (5xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A decision gate's restrict left no eligible lane and its `on_empty` policy is reject (fail-closed), so busbar rejects the request rather than route to an ineligible lane. This is the correct compliance behavior.

## How to fix it

None — self-heals per request; the counters carry the volume. If rejections are unexpected, review the pool membership tags against the restrict's required tags.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
