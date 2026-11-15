---
title: "BUSBAR-3027: A 1.5.5 file overlay holds settings this Store has not imported (boot refuses to start)"
description: "What Busbar error BUSBAR-3027 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3027
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

The overlay file a 1.5.5 deployment read and wrote (config.overlay.file, BUSBAR_CONFIG_OVERLAY, or busbar-overlay.json beside config.yaml) holds admin-API settings, and this Store has no import receipt for it. 1.6 serving never reads file overlays, so starting would silently drop those settings, security hooks and groups included; serving REFUSES to start instead. The message names the file and how it was selected, never its settings. In --safe-mode it is a warning and the boot continues.

## How to fix it

Follow the remedy the message gives for this Store. The upgrade boot folds a 1.5.5 overlay into config.yaml; a config.yaml that is already migrated no longer reads it. Re-apply the settings you still want through the admin API (on a durable Store), keeping a copy of the file first. Moving the file away without a copy abandons the settings deliberately.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
