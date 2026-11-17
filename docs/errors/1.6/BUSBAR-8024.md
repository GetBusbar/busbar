---
title: "BUSBAR-8024: Recoverable credentials are not yet re-sealed under the current at-rest key"
description: "What Busbar error BUSBAR-8024 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8024
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A boot or reload re-seals every stored recoverable credential stored in the clear before 1.6.0 under the key derived from auth.signing_key. Some rows were not re-sealed on this pass: another node held their claim, the store keeps no claims, or the store refused the write. They still authenticate.

## How to fix it

A later boot or reload re-seals them (no further warning). If it persists on a single node, check that the store supports single-use claims and accepts credential writes.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
