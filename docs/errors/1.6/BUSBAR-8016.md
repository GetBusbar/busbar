---
title: "BUSBAR-8016: Governance store is in-memory (ephemeral) — state resets on restart"
description: "What Busbar error BUSBAR-8016 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8016
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' usage, and ledgers live only in RAM and are LOST on restart. This is the default when no durable store plugin is configured — fine for a trial or local development, but not for anything that must retain keys or spend across restarts.

## How to fix it

Configure a durable governance store plugin for persistence if keys, usage, or budgets must survive a restart. No action is needed for ephemeral/dev use.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
