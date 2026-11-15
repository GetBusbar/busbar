---
title: "BUSBAR-9021: A closed writer's shutdown.drain_incomplete record could not be queued (retried)"
description: "What Busbar error BUSBAR-9021 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9021
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This process closed the store writer of a previous process that never retired (a successor on the same host, a recovery adopter, or the start-up expired-lease pass), but the admin audit queue refused its shutdown.drain_incomplete record: the queue was full or no entropy was available. The record is kept, named here with the writer's epoch, id, node and host, retried every second until it is queued and confirmed, and printed at exit if it is still refused. No later process records this writer.

## How to fix it

Check the admin audit store's health: the queue is full because its appends do not complete. The record is retried on its own; if this process exits first, its stderr carries the writer's identity as the only evidence.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
