---
title: "BUSBAR-2051: A request terminal audit original could not be staged"
description: "What Busbar error BUSBAR-2051 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2051
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The journal refused the terminal audit original before native confirmation. The request fails instead of reporting success without its audit evidence; an already streaming response terminates with an error. The journal and audit chain positions do not advance for the refused original. The counter busbar_audit_stage_failures_total counts these failures.

## How to fix it

Check store availability and journal custody pressure. A closed journal can also indicate shutdown. Do not assume an upstream operation was undone when its terminal audit failed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
