---
title: "BUSBAR-3009: plugins.first_party_floors floor is not valid semver (plugin refused unconditionally)"
description: "What Busbar error BUSBAR-3009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3009
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A `plugins.first_party_floors` floor is not a valid MAJOR.MINOR.PATCH version. It cannot be satisfied, and because a first-party floor REPLACES the binary-version floor, the named plugin is refused UNCONDITIONALLY until this is fixed — a stricter failure than an invalid `min_versions` floor.

## How to fix it

Fix or remove the named `plugins.first_party_floors` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that first-party plugin is refused on every boot.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
