---
title: "BUSBAR-4003: Login plugin call panicked (login rejected fail-closed)"
description: "What Busbar error BUSBAR-4003 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4003
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A login plugin's blocking call panicked (the offloaded task returned a join error), so busbar rejects the login fail-closed rather than complete a login it never verified. A panicking plugin is a plugin bug.

## How to fix it

Fix the login plugin — a panic on the login path is a bug in that plugin. Capture the logged method/op context and the plugin's own logs; logins via that method fail until it is corrected.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
