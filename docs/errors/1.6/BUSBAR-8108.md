---
title: "BUSBAR-8108: The admin mutation rate limit is exhausted"
description: "What Busbar error BUSBAR-8108 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8108
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The caller has used its per-minute budget of admin mutations. Reads are not limited.

## How to fix it

Wait for the window the `retry-after` header gives (at most a minute) and retry; batch changes where the API allows.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
