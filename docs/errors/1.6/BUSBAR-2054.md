---
title: "BUSBAR-2054: An unstamped audit tail was sealed after a restart"
description: "What Busbar error BUSBAR-2054 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2054
---

**Area:** Audit chain (2xxx) · **Severity:** benign_recurring · **Since:** 1.6.0

## What it means

A busbar process stopped before its audit notary stamped its last lines. On restart, the node itself (same holder) or the next process on the same host walked the links from the last valid stamp to the tail, found them intact and no longer than any crash leaves, and signed one after_restart page over exactly those lines with the deployment key. The verify tool reports such pages under restart_sealed, apart from live pages, with the sealer node and the down interval.

## How to fix it

None: this is the designed outcome of a crash. Look for the crash itself (exit code, kill, host restart) if it was not expected.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
