---
title: "BUSBAR-9022: A writer lease or host assignment row does not decode (never closed)"
description: "What Busbar error BUSBAR-9022 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9022
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The start-up pass that closes writers whose lease expired at least one lease TTL ago found a writer lease or host assignment row it cannot decode. It never closes or deletes such a row; it reports it once per start with the row's key.

## How to fix it

Inspect the named key in the store's node schema. A row written by another tool or a damaged store needs operator repair; busbar leaves it in place.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
