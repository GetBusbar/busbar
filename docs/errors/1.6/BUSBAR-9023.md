---
title: "BUSBAR-9023: An expired writer was not closed (the next start retries)"
description: "What Busbar error BUSBAR-9023 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9023
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The start-up pass that closes writers whose lease expired at least one lease TTL ago could not close the named writer, could not delete a closed writer's lease row, or could not scan the node schema, usually because the store did not answer. The writer stays open and the next start of any gateway on this store retries.

## How to fix it

Check the store's health. Nothing is lost: the writer is closed, and its shutdown.drain_incomplete record written, by a later start.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
