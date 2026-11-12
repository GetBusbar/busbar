---
title: "BUSBAR-3004: Config overlay written by a newer busbar on apply (refusing to overwrite)"
description: "What Busbar error BUSBAR-3004 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3004
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin apply found the config overlay was written by a NEWER busbar than this binary, so busbar REFUSED to overwrite it: this binary cannot represent everything the newer overlay holds, and a write would silently discard whatever it does not understand. This apply was NOT persisted.

## How to fix it

Apply config mutations from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This binary serves on the overlay it can read but cannot persist changes to it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
