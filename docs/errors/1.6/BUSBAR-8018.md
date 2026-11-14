---
title: "BUSBAR-8018: Group usage read failed (could not derive a bucket's usage from the governance store)"
description: "What Busbar error BUSBAR-8018 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8018
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin group `/usage` read could not derive a bucket's usage from the governance store (a store read error while computing enforcement-matched spend), so the request returns 500 rather than a partial or understated usage view. No governance state is mutated; the read simply could not complete for the named group/bucket.

## How to fix it

Investigate the governance store's health for the logged group and bucket (reachability, the underlying store error). The condition is a read-path fault; usage reads recover once the store answers.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
