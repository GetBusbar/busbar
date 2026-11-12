---
title: "BUSBAR-4007: admin_auth names a module with no resolved plugin"
description: "What Busbar error BUSBAR-4007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4007
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin auth chain named a module that has no resolved plugin, and busbar skipped it fail-closed. This is supposed to be impossible after a successful boot — `AdminAuthChain::build` fails closed on any unresolvable name — so reaching it means the admin-module table drifted from the configured chain.

## How to fix it

Investigate the admin auth configuration and plugin load state; a named admin module is missing at runtime. Restart busbar so boot re-resolves the chain, and file a bug with the logged module name if it persists.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
