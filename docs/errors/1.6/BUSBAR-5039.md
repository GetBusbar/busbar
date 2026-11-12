---
title: "BUSBAR-5039: Plane breaker tripped hard-down (definitive auth/billing failure; sticky cooldown)"
description: "What Busbar error BUSBAR-5039 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5039
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane target answered a DEFINITIVE failure (auth/billing), so busbar trips its breaker hard-down: dispatches fast-fail for a sticky cooldown rather than keep retrying a target that will keep rejecting. Emitted per hard-down disposition for the named target.

## How to fix it

Fix the named target's credentials or billing/quota with its provider — a hard-down is a definitive rejection, not a transient blip. It recovers via the half-open probe once the underlying auth/billing fault is resolved.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
