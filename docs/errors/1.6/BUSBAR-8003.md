---
title: "BUSBAR-8003: Refused to synthesize a governance key (principal id collides with a reserved namespace)"
description: "What Busbar error BUSBAR-8003 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8003
---

**Area:** Governance & cost (8xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A principal id (attacker-influenceable at the IdP) starts with a reserved ledger-bucket prefix (`group:` or `vk_`), which would alias a group's or a real virtual key's ledger and rate bucket. busbar fails closed and synthesizes NO key for that principal rather than mint a colliding bucket. This is a per-request, caller-side signal, not an operator problem, so it is emitted at debug.

## How to fix it

None — self-heals; the principal is correctly refused data-plane access. If a legitimate identity is being rejected, its IdP subject must be reshaped to avoid the reserved `group:` and `vk_` prefixes.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
