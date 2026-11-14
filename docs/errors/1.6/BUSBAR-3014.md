---
title: "BUSBAR-3014: --print-metadata-blocklist printed the built-in denylist only (config unreadable)"
description: "What Busbar error BUSBAR-3014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3014
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --print-metadata-blocklist` could not parse or env-interpolate config.yaml, so it printed the HARDCODED cloud-metadata denylist ALONE and skipped the operator's `security.blocked_metadata_hosts` additions. The list shown is therefore INCOMPLETE — it omits whatever the config would have added — even though the running gateway (once it boots on a valid config) would enforce the full union.

## How to fix it

Run `busbar` (or `busbar --validate`) normally to see the precise parse/interpolation error, fix config.yaml, then re-run the flag to see the full effective denylist. The error itself is not echoed here because it could quote a config value.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
