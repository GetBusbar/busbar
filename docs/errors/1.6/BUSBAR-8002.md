---
title: "BUSBAR-8002: Revocation denylist re-sync failed (keeping the previously-known revocations)"
description: "What Busbar error BUSBAR-8002 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8002
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A revocation-denylist re-sync read from the governance store returned an error, so busbar keeps the previously-known revocations in place (fail-closed: a store blip never widens access) and leaves the set marked stale so the next window retries. A peer's revoke may not be visible on this node until a later sync succeeds.

## How to fix it

Investigate the governance store — a transient error self-heals on the next window's retry; sustained failures mean the store is unreachable and cross-node revocations are not propagating.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
