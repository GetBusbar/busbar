---
title: "BUSBAR-3003: Config overlay unreadable/corrupt on apply (refusing to overwrite)"
description: "What Busbar error BUSBAR-3003 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3003
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin apply tried to read-modify-write the config overlay but found the existing overlay present yet unreadable/corrupt, so busbar REFUSED to overwrite it — a blind overwrite would drop the hook AND group deletion tombstones every section carries and could resurrect a deleted item. This apply was NOT persisted.

## How to fix it

Fix or remove the corrupt overlay file to restore durability, then re-apply. Until then admin config mutations cannot be persisted (they are refused, not silently lost).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
