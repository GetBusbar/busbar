---
title: "BUSBAR-8105: The admin request is malformed or fails validation"
description: "What Busbar error BUSBAR-8105 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8105
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The request body or its parameters are not what the operation takes: a malformed JSON body, an unknown or missing field, a value out of range, or a configuration change that fails the same validation `busbar --validate` runs. The message says which.

## How to fix it

Fix the request as the message describes; the OpenAPI document at /docs/api/ gives each operation's schema.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
