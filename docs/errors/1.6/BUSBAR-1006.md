---
title: "BUSBAR-1006: Admin store operation failed (generic 500; store detail logged server-side)"
description: "What Busbar error BUSBAR-1006 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-1006
---

**Area:** Durability & write-through (1xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An admin API CRUD or read operation against the governance/durable store returned an error, so busbar answers the admin request with a generic 500. The store's own error (which may embed SQL fragments or backend paths) is logged server-side only — the response body carries no store internals. The `operation` field names which call failed.

## How to fix it

Investigate the durable/governance store's health and reachability for the named operation. A transient store hiccup self-heals on retry; sustained failures mean the store backend is unhealthy and admin mutations/reads cannot complete.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
