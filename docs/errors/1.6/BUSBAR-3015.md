---
title: "BUSBAR-3015: --validate rejected the config (load, resolve, semantic, or secret-resolution failure)"
description: "What Busbar error BUSBAR-3015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3015
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --validate` ran the exact load → resolve → semantic-validate → strict-secret pipeline boot runs and the config did NOT pass at one of those phases, so it exits non-zero. Because `--validate` mirrors boot, this same config would fail to boot the gateway. The specific phase and offending entries are printed alongside this code.

## How to fix it

Fix the reported errors in config.yaml / providers.yaml (a parse/structure error, a cross-reference the resolver rejected, a semantic-validation failure, or an unset required secret) and re-run `--validate` until it reports `ok`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
