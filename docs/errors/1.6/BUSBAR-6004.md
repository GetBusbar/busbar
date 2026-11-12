---
title: "BUSBAR-6004: Cannot fingerprint the plugins dir (bypassing the catalog cache)"
description: "What Busbar error BUSBAR-6004 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6004
---

**Area:** Plugins (6xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A real I/O error (not a missing directory) meant the plugins directory could not be fingerprinted, so its content-hash freshness signal cannot be trusted and busbar bypasses the catalog cache for this read, falling through to the real scan. Self-healing: it clears once the directory is readable. Warned once on entry to the failing state; recurrence logs at debug.

## How to fix it

Investigate the plugins directory's readability (permissions, a stale/hung mount). The catalog read still works via the direct scan; the cache re-engages once the directory fingerprints cleanly again.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
