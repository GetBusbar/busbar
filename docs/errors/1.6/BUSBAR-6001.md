---
title: "BUSBAR-6001: plugins.fetch missed on reload (keeping the current artifact)"
description: "What Busbar error BUSBAR-6001 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6001
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

During a reload, fetching a pinned plugin artifact missed (the source did not return a usable download for the pinned spec), so busbar kept the artifact already on disk and continued the reload. The running plugin is unchanged; the intended refresh did not land.

## How to fix it

Check the plugin source (registry/URL) and the pinned spec for the named artifact — a transient fetch miss self-heals on the next reload, a persistent one means the pin no longer resolves. busbar keeps serving the current artifact until a fetch succeeds.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
