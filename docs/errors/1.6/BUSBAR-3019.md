---
title: "BUSBAR-3019: Config-settings overlay read task failed to join (500 rather than a fabricated 200)"
description: "What Busbar error BUSBAR-3019 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3019
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The blocking task that reads the config overlay for `GET /config/settings` failed to join — it panicked, or the runtime is shutting down — so busbar returns 500 rather than a fabricated empty-settings 200 that would misreport "no overrides set" when the read never completed. A panic here is a bug.

## How to fix it

Retry the request; a shutdown-race clears on its own. A repeatable failure is a panic in the overlay read path — capture the logged join error and file a bug.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
