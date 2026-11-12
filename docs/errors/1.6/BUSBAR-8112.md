---
title: "BUSBAR-8112: The admin request body exceeds the configured limit"
description: "What Busbar error BUSBAR-8112 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8112
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The request body is larger than the admin surface accepts.

## How to fix it

Send a smaller body (split a bulk change into several requests), or raise the configured admin body limit.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
