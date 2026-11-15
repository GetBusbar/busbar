---
title: "BUSBAR-9019: Shutdown drain incomplete (the writer was not retired; exit 75 or 70)"
description: "What Busbar error BUSBAR-9019 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9019
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The process stopped serving but did not retire its store writer: the drain budget ran out or a second signal arrived (cause=deadline), requests, governed units or persistence were still unsettled at their cut (cause=undrained), or the store refused the retirement (cause=retire_refused). Nothing in flight was cancelled. The exit status is 75 when every completed request's spend is in durable custody (running streams were cut) and 70 when some completed spend is not; each unsettled item is printed on stderr. The writer stays open until its lease lapses and the next start closes it.

## How to fix it

Read the cause and the stderr lists. For cause=deadline on a slow store, raise the drain budget or fix the store's latency. A 70 exit lists the unpersisted spend as evidence: correct it through the audited admin correction path once the store is back.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
