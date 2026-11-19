---
title: "BUSBAR-3116: A plane is configured while the data-plane auth chain is empty — RETIRED"
description: "What Busbar error BUSBAR-3116 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3116
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: auth is plane-agnostic, and no plane has a refusal of its own. An empty `auth.chain` is refused for every plane alike ("auth.chain is empty: no verifier, so nobody could be admitted"); an open deployment names `auth: { chain: [anonymous] }` and is narrowed by `role_bindings.anonymous` on every plane (MCP and A2A included).

## How to fix it

Nothing emits this code. To serve callers that present no credential, write `auth: { chain: [anonymous] }` and grant them under `role_bindings.anonymous`; see docs/mcp.md.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
