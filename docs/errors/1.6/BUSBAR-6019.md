---
title: "BUSBAR-6019: A plugin reported an error number it did not declare"
description: "What Busbar error BUSBAR-6019 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6019
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin failed a call or wrote a log line with an error number that is not in its D_ERRORS declaration (or declared none), or above 9999. Core kept the plugin's text and wrote no `BUSBAR-<plugin>-NNNN` code for it. This warning fires once per instance; the instance keeps serving.

## How to fix it

Report the plugin to its author with the logged `number`: the plugin's docs/diagnostics.json and its declared numbers disagree (its C-ERRORS conformance case catches this in its own CI).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
