---
title: "BUSBAR-8106: The If-Match version is stale"
description: "What Busbar error BUSBAR-8106 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8106
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The request's `If-Match` names a version of the resource that is no longer current: someone else changed it after you read it. This is retryable.

## How to fix it

Re-read the resource, re-apply your change to the current version, and retry with the new `ETag`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
