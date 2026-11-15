---
title: "BUSBAR-3170: A configuration word, section or style changed its owner after it was read"
description: "What Busbar error BUSBAR-3170 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3170
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

The configuration was read under the grammar its admitted modules declared at that moment. A secret shorthand word, a core grammar role, a plane section or an outbound auth style the configuration uses is declared differently by what admission now gives (plugins.dir changed after the read), or by the Store's plugin version pins at boot, or would be at the next start after a pin. Busbar refuses rather than read a value under one declaration and resolve it under another: a reload or apply is refused and the running generation keeps serving, a boot exits, and a pin is not written. The message names the item and both owners with their files. A module upgraded with an equal declaration never refuses, and an item the configuration does not use never refuses.

## How to fix it

Reload (or restart) to read the configuration again. At boot, make config.yaml's plugins: block admit the same module, write the canonical `{ module: ..., settings: ... }` reference, or start once with --ignore-overlay and remove the pin with POST /api/v1/admin/plugins/rollback.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
