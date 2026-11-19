---
title: "BUSBAR-3029: A retired launch environment variable is set (converted or ignored)"
description: "What Busbar error BUSBAR-3029 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3029
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar 1.6 retired the launch variables BUSBAR_PROVIDERS, BUSBAR_WORKER_THREADS, TOKIO_WORKER_THREADS, BUSBAR_UPSTREAM_HTTP1_ONLY and BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE. None refuses a start: each one set is said once, never echoing its value. BUSBAR_PROVIDERS is read as the providers catalog path, as 1.5.5 read it, unless --providers names one; the two upstream variables are applied over their configuration keys, as 1.5.5 applied them; the two worker variables are ignored, because the worker count is one per CPU core the process may use. Emitted pre-tracing, to stderr, at boot and by --validate.

## How to fix it

Move the value into config.yaml where a key exists (`providers_file:`, the upstream keys), validate, then remove the variable from the launcher.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
