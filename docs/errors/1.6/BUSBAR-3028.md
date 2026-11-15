---
title: "BUSBAR-3028: A 1.5.5 overlay selector, variable or file is not read (nothing to import)"
description: "What Busbar error BUSBAR-3028 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3028
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The deployment still carries a 1.5.5 file-overlay input that 1.6 serving does not read: a config.overlay selector or BUSBAR_CONFIG_OVERLAY naming a file that does not exist, an overlay file that holds no settings, a file whose settings this Store has already imported, or a file beside a locked config (which 1.5.5 ignored too). Nothing is lost, so the boot continues; the message names the file and how it was selected.

## How to fix it

Remove the leftover input: delete the imported or empty overlay file, and remove BUSBAR_CONFIG_OVERLAY from the launcher. Remove `config.overlay` from config.yaml. See docs/migration-1.6.md.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
