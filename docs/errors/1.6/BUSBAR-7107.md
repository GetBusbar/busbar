---
title: "BUSBAR-7107: An admin plane record write named a kernel record kind (the write is refused)"
description: "What Busbar error BUSBAR-7107 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7107
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`POST /api/v1/admin/plane-record-write` named a record kind the kernel keeps its own records under (`audit`, `usage_residual`, `demotion`, `trust_decision` or `ticket`). A plane may declare one of these (a plane may declare `demotion`), but the rows under it are the kernel's own, for example its durable demotion record of a quarantined upstream, and no write made in a plane's name may alter them. busbar answers `403 forbidden` naming the kind, writes nothing, and seals the refusal on the administrative audit ring as `rejected`.

## How to fix it

Do not write kernel records through the plane record verb. To lift a quarantine, approve the counterparty with `POST /api/v1/admin/trust/approve`, which clears its durable demotion. Write a plane's own records under a kind that is not the kernel's.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
