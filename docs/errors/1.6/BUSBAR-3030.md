---
title: "BUSBAR-3030: An auth plugin states the operator credential but is not first-party (ignored)"
description: "What Busbar error BUSBAR-3030 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3030
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admitted auth plugin states the operator credential, but it is not first-party (not signed by a busbar release key), so it never becomes the operator credential. Nothing in the configuration references it, so it is ignored and the boot continues; each boot also writes an auth.operator.inert audit row naming it.

## How to fix it

Remove the plugin from plugins.dir, or narrow plugins.trust so it is not admitted. To make a plugin the operator credential, install the first-party operator credential plugin.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
