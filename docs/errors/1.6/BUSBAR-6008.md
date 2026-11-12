---
title: "BUSBAR-6008: Plugin rollback rebuild failed AND reverting the version pin failed (disk out of sync)"
description: "What Busbar error BUSBAR-6008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6008
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin rollback's rebuild failed AFTER the lowered pin was persisted, and the compensating revert of that pin ALSO failed, so disk now carries the rolled-forward pin while the running engine still serves the prior plugin. A restart would honor the stale on-disk pin and contradict the running engine. Loud because disk and the live engine now disagree.

## How to fix it

Fix the config overlay so the version pin matches the plugin the running engine serves BEFORE restarting (the log names the plugin and both errors). Until then a restart would come up in a state the running engine rejected.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
