---
title: "BUSBAR-6003: Plugin loaded UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
description: "What Busbar error BUSBAR-6003 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6003
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin was loaded even though its signature is UNVERIFIED — its code is running unauthenticated, permitted only because an explicit `plugins.trust` opt-in (`allow_untrusted`) let it through. Security-relevant: unverified plugin code runs in-process with busbar's privileges. Emitted once per such plugin at boot.

## How to fix it

Prefer a signed artifact from a trusted publisher and remove the `plugins.trust` opt-in once you no longer need it. If running unverified is a deliberate, understood choice (e.g. a locally-built plugin), the opt-in is what keeps it explicit.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
