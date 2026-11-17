---
title: "BUSBAR-3135: A registration still carries the retired per-registration private-address switch"
description: "What Busbar error BUSBAR-3135 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3135
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code. A plane registration (an MCP server, an A2A agent) may set `allow_private`: core reads it as a boolean at the registration its plane declares and grants private reach to that registration's selected route alone, never to another registration, a provider, a request-supplied URL or a callback. A value that is not a boolean, or `allow_private` on a stdio registration, is refused naming the registration. `advanced.allow_destinations` was removed.

## How to fix it

Nothing emits this code. Set `allow_private: true` only on the registration that must reach a private target; cloud metadata and the gateway's own listeners stay refused whatever is written.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
