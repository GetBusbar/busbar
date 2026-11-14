---
title: "BUSBAR-8110: The admin call could not complete within its bound"
description: "What Busbar error BUSBAR-8110 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8110
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An operation that is normally fast could not start or finish in time (for example the plugin catalog scan), or no administrative surface is mounted on this listener. The call was abandoned rather than left to hang.

## How to fix it

Retry after a short wait. If it persists, check the server log and the store's health.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
