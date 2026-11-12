---
title: "BUSBAR-6010: --list-plugins could not build a trust policy (plugins.trust is invalid)"
description: "What Busbar error BUSBAR-6010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6010
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --list-plugins` could not compile a trust policy from the `plugins.trust` block (e.g. an unparsable trust anchor or a malformed policy), so it cannot compute per-tarball signature verdicts and exits non-zero. The running gateway would reject this same `plugins.trust` at boot.

## How to fix it

Fix the `plugins.trust` block (the logged error names the problem), then re-run `--list-plugins` or `--validate`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
