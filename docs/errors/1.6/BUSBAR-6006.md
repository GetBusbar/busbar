---
title: "BUSBAR-6006: Plugin catalog blocking task failed to join (fail-soft to the compiled-in row)"
description: "What Busbar error BUSBAR-6006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6006
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The plugin catalog store scan ran on a `spawn_blocking` task that failed to join (cancelled or panicked). busbar fails SOFT to the always-true compiled-in catalog row rather than a 500 — this is just a plugin CATALOG read — the same posture it takes on an unparseable plugins_cfg. Rare.

## How to fix it

Investigate the logged context if it recurs — a blocking-task join failure on the catalog read is unusual. The catalog is served fail-soft in the meantime, so the admin read still returns.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
