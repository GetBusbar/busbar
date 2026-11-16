---
title: "BUSBAR-9010: jemalloc idle-purge fallback unavailable (idle RSS may not return to the OS)"
description: "What Busbar error BUSBAR-9010 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9010
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The fallback idle-purge helper (for targets where jemalloc's background purge threads are compiled out, e.g. macOS) could not start — its worker thread failed to spawn, or it could not read `opt.dirty_decay_ms`. A fully IDLE process may therefore hold freed-but-unpurged dirty pages and its RSS can ratchet at the last burst's peak until traffic resumes. Request behavior is unaffected.

## How to fix it

Usually benign — RSS is reclaimed the moment traffic resumes, and under load the helper does nothing. If steady idle RSS on a macOS build matters, investigate the logged spawn/mallctl error; the gateway serves normally regardless.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
