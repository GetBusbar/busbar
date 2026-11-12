---
title: "BUSBAR-1002: Durable audit log has another writer — this node detached its durable sink — RETIRED"
description: "What Busbar error BUSBAR-1002 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1002
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.

## How to fix it

Nothing emits this code. See BUSBAR-2044.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
