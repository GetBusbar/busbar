---
title: "BUSBAR-3017: Config-settings read found the overlay unreadable/corrupt (reported no root overrides)"
description: "What Busbar error BUSBAR-3017 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3017
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A `GET /config/settings` read found the persisted config overlay present but unreadable/corrupt, so it returned an EMPTY set of root overrides. Nothing is mutated, but the response cannot be distinguished from a genuine "no overrides set" — the operator's stored single-value overrides may exist on disk yet be absent from this answer.

## How to fix it

Fix or remove the corrupt overlay file to restore durable reads (see BUSBAR-3005 for the boot-time counterpart). Until then this endpoint under-reports the stored root settings.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
