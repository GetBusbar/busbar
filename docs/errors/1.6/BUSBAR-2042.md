---
title: "BUSBAR-2042: Plane per-call records failed hash-chain verification on restore (tamper evidence) — RETIRED"
description: "What Busbar error BUSBAR-2042 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2042
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. A principal's persisted plane per-call records were read at boot but do NOT verify against their own hash chain, which is tamper evidence. They are still restored and the chain resumes from the broken tail, because refusing here would convert a detection control into a deletion primitive — anyone able to write to the store could delete a caller's history by corrupting one record.

## How to fix it

Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
