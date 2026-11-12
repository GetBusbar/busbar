---
title: "BUSBAR-9011: --generate-signing-key could not mint a key (OS entropy source unavailable)"
description: "What Busbar error BUSBAR-9011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9011
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --generate-signing-key` could not mint a fresh ed25519 signing secret because the OS entropy source was unavailable, so it printed nothing and exited non-zero. No key was generated and nothing was written.

## How to fix it

Retry on a host with a working RNG (`/dev/urandom` / `getrandom`). A persistent failure points at a broken or blocked entropy source in the environment.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
