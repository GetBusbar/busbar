---
title: "BUSBAR-6005: Plugin catalog scan gate not acquired within the wait bound (retryable 503)"
description: "What Busbar error BUSBAR-6005 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6005
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin catalog scan could not acquire the scan gate within its bounded wait, which signals a PRIOR scan is not returning — typically a stale or hung plugins_dir mount. busbar answers with a retryable Unavailable (503) rather than hang this request behind the wedged scan.

## How to fix it

Investigate the plugins_dir mount — a hung scan usually means the directory's filesystem is stalled (e.g. an unresponsive network mount). Resolve the mount; the gate frees once the prior scan returns or is unwedged.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
