---
title: "BUSBAR-9026: This node is in restore quarantine: the Store was restored and is not yet declared"
description: "What Busbar error BUSBAR-9026 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9026
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This node will not serve the data plane or mutate state, because the Store it opened was restored from a backup or another node began a restore. It entered quarantine because it was started with --restore-quarantine (reason flag), because the Store's restore row says a restore is pending (pending_row), or because a node-lease refresh saw a restore epoch other than the one this process started with (epoch_changed). The line names the reason, the restore epoch and, once a tail is supplied, the covered nodes, the per-node gaps and what was not re-applied. /readyz answers 503 with the reason store_restored; /livez stays up; admin reads are served.

## How to fix it

Finish the restore: verify the exported audit tail with POST /api/v1/admin/store-restore/verify, then declare it with POST /api/v1/admin/store-restore (docs/operations.md, Backup set and order). Start the node launched with --restore-quarantine first and the other nodes only after it reports this line. A node that entered quarantine at a lease refresh restarts after the declaration.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
