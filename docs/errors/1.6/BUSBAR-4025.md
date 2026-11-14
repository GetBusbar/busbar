---
title: "BUSBAR-4025: oauth_as generated an ephemeral ES256 signing key (tokens die on restart)"
description: "What Busbar error BUSBAR-4025 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-4025
---

**Area:** Auth & identity (4xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The oauth_as authorization server has no `signing_key` configured, so busbar generated an EPHEMERAL ES256 key at boot. Every token this deployment issues is signed with that in-memory key and stops verifying the moment the process restarts, because a new key is generated on the next boot. Acceptable only for a trial or local development.

## How to fix it

Set `oauth_as.signing_key` to a durable key reference before relying on issued tokens across restarts. Until then, every restart invalidates all outstanding oauth_as tokens.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
