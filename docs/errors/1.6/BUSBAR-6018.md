---
title: "BUSBAR-6018: A plugin's error-number declaration was refused; it runs without error codes"
description: "What Busbar error BUSBAR-6018 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6018
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The plugin declared its error numbers (D_ERRORS) in a form core does not accept: more than one declaration, an empty, odd or over-long body, a number 0 or above 9999, numbers out of ascending order (or repeated), or a plugin name that cannot form a code. The plugin was admitted and serves; its failures and log lines carry their text with no `BUSBAR-<plugin>-NNNN` code. `have` names the fault (counts, numbers and byte positions only) and `want` the accepted form. The image's admission record carries the same fault.

## How to fix it

Report the plugin to its author: its declared numbers must be 1..=256 numbers, each 1..=9999, strictly ascending, under a name matching ^[a-z][a-z0-9-]{0,63}$ that does not end in '-'. Nothing to change in the configuration.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
