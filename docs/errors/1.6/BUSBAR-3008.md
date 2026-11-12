---
title: "BUSBAR-3008: plugins.min_versions floor is not valid semver (anti-downgrade disarmed)"
description: "What Busbar error BUSBAR-3008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3008
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A `plugins.min_versions` anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (e.g. a stray leading `v`). It cannot be satisfied, so the floored plugin is refused, and — more subtly — an operator who believes the anti-downgrade control is armed does not get the protection they configured.

## How to fix it

Fix or remove the named `plugins.min_versions` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that plugin is refused and the anti-downgrade floor for it is effectively disarmed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
