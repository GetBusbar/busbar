---
title: "BUSBAR-3007: Config overlay patch does not parse (entry not applied)"
description: "What Busbar error BUSBAR-3007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3007
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The config overlay holds a named-map patch that, merged against base config, does not produce a definition this binary can parse (it faces the same typed `deny_unknown_fields` parse config.yaml does). busbar drops the entry WHOLE rather than half-apply it, so that named definition is never applied and sits inert in the overlay.

## How to fix it

Edit or remove the offending overlay entry (the log names the section and entry), then reload. The operator's stored data is untouched; the entry is simply not applied until it parses.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
