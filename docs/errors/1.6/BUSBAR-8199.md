---
title: "BUSBAR-8199: The admin request was refused"
description: "What Busbar error BUSBAR-8199 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8199
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The admin surface refused the request for a reason the `error.code` field names. This code covers refusals without a more specific admin code.

## How to fix it

Read `error.code` and `error.message` in the response; docs/admin-api.md lists every error code.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
