---
title: "BUSBAR-5045: Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set)"
description: "What Busbar error BUSBAR-5045 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-5045
---

**Area:** Proxy & routing (5xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The deployment set the nuclear `allow_all_metadata` escape hatch, so busbar's cloud-metadata SSRF guard is OFF and EVERY cloud-metadata endpoint (e.g. 169.254.169.254, the GCP/Azure metadata hosts) is reachable through the proxy. That is a security-relevant degradation: a crafted upstream URL or a compromised plugin can reach the instance's credential endpoint. Emitted once at boot.

## How to fix it

Remove `allow_all_metadata` unless a specific, understood need requires it. If metadata access is genuinely needed, scope it with `security.blocked_metadata_hosts` instead of disabling the guard wholesale (`--print-metadata-blocklist` shows the effective list).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
