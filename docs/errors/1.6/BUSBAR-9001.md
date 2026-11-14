---
title: "BUSBAR-9001: Durable audit log could not be read at boot (starting with an empty ring)"
description: "What Busbar error BUSBAR-9001 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9001
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar could not READ the durable audit log from the governance store at boot — a store hiccup, not a chain-verification failure — so it started with an empty in-memory audit ring. This is deliberately distinct from BUSBAR-2043 (chain verification failed): here the bytes could not be read at all, so there is no tamper signal, just a store that did not answer.

## How to fix it

Investigate the governance store's reachability at boot. If the store recovers, restart so the durable history is restored into the ring; a transient hiccup needs no action beyond confirming the store is healthy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
