---
title: "BUSBAR-6002: Plugin present but NOT loaded (skipped by trust policy)"
description: "What Busbar error BUSBAR-6002 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6002
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin artifact is present in the plugins directory but was NOT loaded because the configured trust policy skipped it (unsigned, an untrusted publisher, or a failed signature/floor check), or because this build's crypto backend admits no external plugin (a FIPS build loads only busbar's own verified release, whatever `plugins.trust` allows; reason code `external_crypto`). busbar fails closed: an untrusted plugin is left inert rather than loaded. Emitted once per skipped plugin at boot.

## How to fix it

If the plugin should load, sign it with a trusted publisher key or add that publisher to `plugins.trust` (the log names the plugin, file, and reason). Under `external_crypto` no `plugins.trust` setting helps: install busbar's first-party release of the plugin. If the skip is intended, remove the artifact from the directory to silence the notice.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
