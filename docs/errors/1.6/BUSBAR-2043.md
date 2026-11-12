---
title: "BUSBAR-2043: Admin audit records failed hash-chain verification on restore (tamper evidence)"
description: "What Busbar error BUSBAR-2043 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2043
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The persisted admin audit records were read at boot through the durable journal seam but do NOT verify against their own hash chain, which is tamper evidence. They are still restored and the chain resumes from the broken tail, because refusing here would convert a detection control into a deletion primitive — anyone able to write to the store could delete audit history by corrupting one record.

## How to fix it

Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
