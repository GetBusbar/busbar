---
title: "BUSBAR-5045: Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set) — RETIRED"
description: "What Busbar error BUSBAR-5045 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5045
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: 1.6.0 refuses `security.allow_all_metadata` at startup (BUSBAR-3136), and cloud metadata is refused for every outbound connection, so the guard can no longer be disabled.

## How to fix it

Nothing emits this code. See BUSBAR-3136.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
