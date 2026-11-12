---
title: "BUSBAR-8013: Provider api_key did not resolve (degraded to an empty key) — RETIRED, see BUSBAR-8020"
description: "What Busbar error BUSBAR-8013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8013
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that provider to an empty key and started the lane anyway. 1.6.0 removed that degrade: an `api_key` that does not resolve now REFUSES BOOT (BUSBAR-8020), and an upstream that genuinely takes no credential is declared with `api_key: none`.

## How to fix it

Nothing emits this code. See BUSBAR-8020.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
