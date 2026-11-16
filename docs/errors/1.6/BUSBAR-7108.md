---
title: "BUSBAR-7108: A plane's destination judge is not installed (every JUDGE answers internal)"
description: "What Busbar error BUSBAR-7108 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-7108
---

**Area:** Plane protocols (7xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane asked core to judge a destination (the JUDGE intent) and the process has no destination judge installed, so core answered `DEST_INTERNAL` (fail closed) for it, and every later JUDGE answers the same until a judge is installed. The plane never learns an address, and a plane that dials nothing is unaffected. busbar logs this once per process.

## How to fix it

Install the destination judge the process builds at boot (the egress guard that backs `dest.judge`), then restart. Until then a plane that depends on JUDGE refuses the destinations it would have judged.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
