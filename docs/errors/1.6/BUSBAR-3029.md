---
title: "BUSBAR-3029: A retired launch environment variable is set and IGNORED"
description: "What Busbar error BUSBAR-3029 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3029
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar 1.6 no longer reads BUSBAR_PROVIDERS, BUSBAR_WORKER_THREADS, BUSBAR_UPSTREAM_HTTP1_ONLY or BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE. A set one has NO effect: the config key (or its default) is in force. Emitted pre-tracing, to stderr, at boot and by --validate.

## How to fix it

Write the value into config.yaml, validate, then remove the variable from the launcher.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
