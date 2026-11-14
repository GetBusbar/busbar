---
title: "BUSBAR-5032: Metrics recorder install failed; /metrics will be empty"
description: "What Busbar error BUSBAR-5032 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5032
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The host's metrics recorder failed to install at boot, so the /metrics endpoint will be empty for the life of the process. busbar continues serving proxy traffic, but is blind to metrics.

## How to fix it

Investigate the boot error (often a duplicate recorder install or a conflicting exporter). Restart busbar after resolving it; /metrics stays empty until then.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
