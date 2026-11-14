---
title: "BUSBAR-3011: auth.chain entry grants max_admin_scope: full"
description: "What Busbar error BUSBAR-3011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3011
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An auth chain entry sets `max_admin_scope: full`, so every principal identified by that module can hold FULL admin authority — the default ceiling is read-only. A security advisory: a compromised or over-broad identity source behind that module becomes an admin-authority source.

## How to fix it

Confirm the named module's chain is trusted end to end and that granting full admin to everyone it identifies is intended. Lower `max_admin_scope` (or scope the module's principals) if full admin is broader than needed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
