---
title: "BUSBAR-2055: An audit chain is broken after its last valid stamp; the tail is recorded, never sealed"
description: "What Busbar error BUSBAR-2055 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2055
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

On restart the walk from a node's last valid audit stamp to its tail failed: a line does not link or hash (link, sequence, digest), a body does not decode (decode), a stamp failed its own check (stamp), a legacy line carries no signature (unsigned), the tail has no stamp of this node on this host (unanchored), it follows a clean-shutdown page (after_final), it is longer than any crash leaves (span), the walk ran out of budget (budget), or a fenced node has no seal row (unsealed_fenced). A signed break notice records the node, the last good line and the unsealed range; no stamp vouches for those lines. Boot continues.

## How to fix it

Treat the named lines as unauthenticated until explained: compare the store with a backup or the export of earlier audit pages. The fields node, last_good, unsealed_from, unsealed_to and reason locate the damage.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
