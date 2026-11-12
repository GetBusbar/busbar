---
title: "BUSBAR-6007: Plugin rollback could not persist the version pin (nothing swapped, fail-closed)"
description: "What Busbar error BUSBAR-6007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6007
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin rollback tried to persist the lowered version pin to the config overlay and the write failed, so busbar FAILS CLOSED and swaps nothing — the running engine still serves the current plugin. Persisting the pin is the whole point of the rollback: a swallowed failure would swap the live engine while disk still carried the rolled-forward state, so a restart would silently re-upgrade.

## How to fix it

Investigate the config overlay's writability (the log names the plugin). Fix the overlay path/permissions and re-issue the rollback; nothing was changed, so it is safe to retry.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
