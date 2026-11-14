---
title: "BUSBAR-3006: Config overlay written by a newer busbar (boot refuses to start)"
description: "What Busbar error BUSBAR-3006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3006
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

At boot the config overlay is intact and meaningful but was written by a NEWER busbar than this one. Ignoring it would run without hooks and groups the operator believes are persisted — security gates included — so the boot caller REFUSES to start rather than silently disarm them.

## How to fix it

Boot a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This is a deliberate boot refusal, not a crash — resolve the version mismatch and restart.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
