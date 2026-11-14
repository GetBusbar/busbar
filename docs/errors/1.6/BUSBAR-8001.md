---
title: "BUSBAR-8001: Revocation denylist re-sync still outstanding from an earlier window"
description: "What Busbar error BUSBAR-8001 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8001
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A revocation-denylist re-sync launched in an earlier window has not returned — the governance store has not answered for at least a full sync window — so busbar keeps serving the last-known revocations and does not start a second overlapping read. A peer's revoke may not be visible on this node until the store recovers. The CAS bound rate-limits this warning to once per window.

## How to fix it

Investigate the governance store's health and latency. Revocations already known stay enforced (fail-closed); the risk is a NEW revoke made elsewhere not yet reaching this node. Re-sync resumes automatically once the store answers.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
