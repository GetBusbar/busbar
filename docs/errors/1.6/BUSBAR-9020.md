---
title: "BUSBAR-9020: Completed spend not in durable custody at exit (exit 70)"
description: "What Busbar error BUSBAR-9020 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9020
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

At a shutdown that could not retire the writer, at least one finished request's spend (a terminal unit checkpoint, a budget cell, a metering count or a correction) was not persisted, or its write was still unconfirmed. Each item is printed on stderr with its identity and amounts, as evidence; busbar never imports it on the next start, because an import can double-spend.

## How to fix it

Restore the store, then reconcile the listed items through the audited admin correction path. Find why the drain could not persist them (store outage or latency at shutdown).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
