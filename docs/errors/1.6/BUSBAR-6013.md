---
title: "BUSBAR-6013: Plugin-supplied text exceeded its cap and was cut"
description: "What Busbar error BUSBAR-6013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6013
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plugin or hook sent text longer than its documented cap: a hook reject message, a metric help, label, unit or label value, or a plugin diagnostic message or field. busbar kept the first `cap` sanitised characters exactly as 1.5.5 did, with nothing appended (for a reject whose kept text is all whitespace, clients see the default reject message instead). This warning fires once per plugin and field for the life of the process; `busbar_plugin_text_cut_total{plugin,field}` counts over-cap values received in plugin and hook replies (counted at parse, including values in metrics later refused).

## How to fix it

Shorten the named plugin's text for the named field to within the cap; the log gives the cap and the text's length after sanitising (control and format characters removed).

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
