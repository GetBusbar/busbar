---
title: "BUSBAR-3018: Config-settings read found a newer-busbar overlay (reported no root overrides)"
description: "What Busbar error BUSBAR-3018 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3018
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A `GET /config/settings` read found the config overlay was written by a NEWER busbar than this binary, so — rather than misrepresent fields it cannot parse — it returned an EMPTY set of root overrides. The response cannot be distinguished from a genuine "no overrides set", so stored overrides may exist yet be absent from this answer.

## How to fix it

Read config settings from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands (see BUSBAR-3006 for the boot-time counterpart).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
