---
title: "BUSBAR-8028: A plugin's rotated credential could not be applied"
description: "What Busbar error BUSBAR-8028 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8028
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar re-reads the secret references a secret or auth plugin instance was opened with every 30 seconds. When one changed (a rotated token file, for example a workload-identity token), busbar hands the new material to the plugin's refresh, or, for a plugin with no refresh, opens a new instance from the same plugin artifact and swaps it in. This failed: the reference could not be re-read (cause unresolvable), the plugin refused the new material (cause refused, at ERROR), or the new instance did not open (cause reopen-failed, at ERROR). The running instance and the credentials it holds are kept and the change is retried on the next poll. Reported at most once a minute per instance and audited as plugin.credential.rotate, degraded; a later success is audited as applied.

## How to fix it

Check the reference and the error field. For refused or reopen-failed, the plugin rejected the rotated material: fix it at the source. If the old material expires first, the plugin's own calls fail until the new material is accepted.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
