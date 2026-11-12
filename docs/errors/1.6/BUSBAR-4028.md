---
title: "BUSBAR-4028: create_key allowed_pools names an unconfigured pool (key still created)"
description: "What Busbar error BUSBAR-4028 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4028
---

**Area:** Auth & identity (4xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A create_key request listed an `allowed_pools` entry that names no configured pool — a likely typo. The key is still created (the entry activates if the pool is configured later), so this is a non-fatal advisory. It is a per-request, caller-side signal, so it is emitted at debug.

## How to fix it

None required — the key was created. If the pool name was a typo, correct it or configure the named pool so the allowed_pools entry takes effect.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
