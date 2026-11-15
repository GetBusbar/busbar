---
title: "BUSBAR-6014: A plugin call was refused by an ABI rule"
description: "What Busbar error BUSBAR-6014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6014
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin asked for something the ABI does not allow: `dest.judge` under the operator-infrastructure egress class (content-named hosts are judged in the default or open-web class), or a mid-stream upgrade offering a name that is not the dialled host (only a dial to an IP literal may offer another name). The call is refused; the first refusal per instance is logged and audited.

## How to fix it

Upgrade the plugin to a release built against busbar 1.6.0, or report the plugin to its author.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
