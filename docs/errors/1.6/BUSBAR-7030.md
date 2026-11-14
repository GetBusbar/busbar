---
title: "BUSBAR-7030: Stateful plane on the in-memory store — plane task state is lost on restart"
description: "What Busbar error BUSBAR-7030 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7030
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar resolved the in-memory (ephemeral) store while a STATEFUL plane is configured — a plane subject (a tool, an agent, or a pool of them). Such planes carry per-task state that lives only in RAM with this store, so it is DROPPED on restart: a task that was mid-flight when the process restarts will break on its next request. Stateless planes are deliberately NOT warned — a restart costs them nothing, so warning there would be noise. This is a WARN, not a boot refusal: a durable store is opt-in and RAM is the convenience default.

## How to fix it

Configure a durable store plugin so plane task state survives a restart. No action is needed if losing in-flight task state on restart is acceptable for this deployment.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
