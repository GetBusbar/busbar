---
title: "BUSBAR-2048: A plane journal scope failed hash-chain verification on resume (tamper evidence)"
description: "What Busbar error BUSBAR-2048 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2048
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane journal scope that had been evicted from the in-memory cache was read back from               the durable store to take its next record, and the persisted tail does NOT verify               against its own hash chain, which is tamper evidence surfaced at runtime rather than at               boot. The chain resumes from the broken tail and the write is not refused, because               refusing here would convert a detection control into a deletion primitive.

## How to fix it

Treat the durable governance store as compromised until explained: capture it for              forensic review before it is overwritten, then restore from a trusted backup once the              cause is understood.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
