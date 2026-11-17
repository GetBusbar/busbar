---
title: "BUSBAR-3025: A provider URL names a private or loopback host the destination guard refuses"
description: "What Busbar error BUSBAR-3025 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3025
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Configured providers retain private reach on their core-selected base/token routes. The grant is restricted to those origins and never becomes a global hostname permission. Metadata remains refused.

## How to fix it

Nothing emits this code. Review the configured provider route; arbitrary requests and strict OPEN_WEB checks do not inherit its private reach.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
