---
title: "BUSBAR-6009: --validate plugin pre-flight failed (structure, trust, conflict, or store resolution)"
description: "What Busbar error BUSBAR-6009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6009
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --validate` ran the same plugin pre-flight boot runs — consistency, trust-policy resolution, the three-phase scan of every tarball (structural → trust → conflict), and store resolution — and it FAILED. Because this is the boot pipeline (manifest-only, no dlopen), the same plugin set would fail the plugin half of boot.

## How to fix it

Fix the reported plugin problem: a malformed manifest, a signature/trust-policy rejection, an ABI-floor or version-floor violation, a name/alias conflict, or a `store.module` that names no installed store plugin (the published binary links no store: install a plugin of kind `store` and select it by its name). Re-run `--validate` until it reports `ok`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
