---
title: "BUSBAR-5008: on_error fallback hook failed; continuing down the chain"
description: "What Busbar error BUSBAR-5008 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5008
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An `on_error` fallback hook itself returned an error, so busbar continued down the fallback chain to the next link (or the reserved terminal). The fallback chain meant to cover a broken primary is itself partly broken. Warned once per fault window.

## How to fix it

Fix the failing fallback hook. The request is still served by a later chain link or the terminal policy, but the chain has less depth than configured.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
