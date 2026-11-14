---
title: "BUSBAR-2047: Persisted admin audit record could not be decoded on restore (skipped, not dropped)"
description: "What Busbar error BUSBAR-2047 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2047
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A persisted admin audit record could not be decoded at boot on the neutral `plane_records` path — a body from a store format no released build wrote, or a corrupt or tampered row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole restore, but the skip is reported here so a silently lost evidence row on this tamper-evidence surface is never invisible. On the admin audit log an undecodable row may be tamper evidence, not merely a format mismatch.

## How to fix it

Treat the durable governance store as suspect: if rows are unreadable on a store a released build wrote, capture it for forensic review before it is overwritten and restore from a trusted backup once the cause is understood.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
