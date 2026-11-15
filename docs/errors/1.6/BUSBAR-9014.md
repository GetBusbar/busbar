---
title: "BUSBAR-9014: Took over a stalled first start (the previous owner is retired)"
description: "What Busbar error BUSBAR-9014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9014
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An unpublished first start of this dataset was owned by another writer whose progress rows stayed byte-for-byte unchanged for the whole stall window (90 s plus 35 s per plane already done), so this process retired that writer and now owns the first start. Logged only when the takeover Register applied. The line names the dataset, the previous and new writer ids, the stall, the window and the observed digest. The previous owner, if still alive, is fenced and fails boot asking for reconciliation.

## How to fix it

Find out why the previous owner stopped: it crashed, was killed, or hung past its own deadlines (a plugin READY, an unavailable store). No action is needed for the dataset; this process finishes first start.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
