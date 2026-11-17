---
title: "BUSBAR-2056: A crashed predecessor on this host was not sealed"
description: "What Busbar error BUSBAR-2056 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2056
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The start-up predecessor sealer found a node on this host that it may not seal: the process has no host name (host_unknown), the node's host or archive row does not match its id reservation (assignment), its last stamp names another host (foreign_host), its liveness at this process's start cannot be shown (sibling_unknown), its seal row does not verify (seal_row_invalid), its records use a recipe this build cannot read (recipe_unsupported), or a step failed for good (permanent). No seal outcome was written for it; any completed writer fence remains in force, and its tail stays reported as unauthenticated, and the next process on the host retries it.

## How to fix it

For host_unknown, set HOSTNAME to a value unique to the machine. For assignment or seal_row_invalid, treat the store as tampered until explained. For the rest, check the store and start the next process on the host.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
