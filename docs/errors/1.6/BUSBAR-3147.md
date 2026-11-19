---
title: "BUSBAR-3147: System CA bundle entries were not used"
description: "What Busbar error BUSBAR-3147 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3147
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

With `outbound.tls.roots: system`, certificates in the operating system's CA bundle that are expired, are not CA certificates, or do not parse are not used as trust anchors. One warning at boot carries the count and the first reason. Operating-system bundles routinely carry such entries, so the boot continues.

## How to fix it

Usually nothing. If a CA you rely on is in the count, update the base image's ca-certificates package or list the CA under `outbound.tls.trust_anchors`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
