---
title: "BUSBAR-2052: An exporter first observed lost delivery or failed evidence"
description: "What Busbar error BUSBAR-2052 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2052
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The exporter retained its first delivery-loss, capture-refusal or audit-integrity failure for transfer to native audit custody. This warning is emitted once per logical instance. Later observations still update their distinct counters. Held ciphertext is not lost delivery.

## How to fix it

Check the exporter destination, admission and audit availability. Inspect the export counters for current counts. This warning does not mean that native audit has confirmed the first-loss record.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
